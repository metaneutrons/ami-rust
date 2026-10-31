/* Native bridge for the bounded M1 SDK. AROS contracts: see THIRD_PARTY_NOTICES.md. */
#include "sdk.h"
#include <exec/execbase.h>
#include <exec/memory.h>
#include <exec/ports.h>
#include <exec/tasks.h>
#include <exec/io.h>
#include <devices/timer.h>
#include <dos/dosextens.h>
#include <intuition/classes.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include "compatibility-gates.h"
#include "test-controls.h"
#ifdef AMI_SDK_TESTING
#include "test-file-controls.h"
#endif

#define KIND_FILE 1UL
#define KIND_LIBRARY 2UL
#define KIND_SIGNAL 3UL
#define KIND_PORT 4UL
#define KIND_MESSAGE 5UL
#define KIND_DEVICE 6UL
#define KIND_REQUEST 7UL
#define IO_KIND_STANDARD 0
#define IO_KIND_TIMER 1
#define IO_IDLE 0
#define IO_PENDING 1
#define IO_MAX_DATA 65536
#define OUTPUT_TOKEN UINT64_C(0xff00000000000001)
#define ERROR_OUTPUT_TOKEN UINT64_C(0xff00000000000002)
struct Block { struct Block *next,*prev;void *user;size_t size,align,total,charge; };
/* Every registry record starts with its token so lookups can validate it. */
struct FileSlot { uint64_t token;BPTR handle; };
struct LibSlot { uint64_t token;struct Library *handle; };
struct SignalSlot { uint64_t token;int bit,port_owned; };
struct PortSlot { uint64_t token;struct MsgPort *handle;int signal_slot; };
struct MessageSlot { uint64_t token;struct Message native;uint8_t payload[256];size_t size;uint64_t queued_port,reply_port;int queued,state; };
/* Records are allocated one by one and never move, so a queued native
   message keeps its address while the table that indexes it grows. */
struct Registry { void **items;size_t capacity,count; };
/* A device owns its reply port; every request of the device replies there.
   Requests own their IORequest and data copy, so no Rust pointer is ever
   reachable by the device and the layout of timerequest stays in this file. */
struct DeviceSlot { uint64_t token;struct IORequest *open;size_t size,requests;uint64_t port; };
struct IoSlot { uint64_t token,device;struct IORequest *request;size_t size;uint8_t *buffer;size_t capacity;int kind,state; };
#define SLOT_BITS 20U
#define SLOT_LIMIT ((UINT64_C(1)<<SLOT_BITS)-1)
#define SEQUENCE_LIMIT ((UINT64_C(1)<<36)-1)
#define SIGNAL_SLOTS 32
static struct Registry files,libraries,ports,messages,devices,requests;
static struct SignalSlot signals[SIGNAL_SLOTS];
static APTR registry_pool;
static uint64_t slot_limit=SLOT_LIMIT;
static struct Block *blocks;
static struct Task *owner;
static struct Library *mandatory_dos;
static int active,closing,callback_active,claimed,initialized,fatal_started;
static jmp_buf cleanup_resume;
static int cleanup_resume_ready,cleanup_error;
static int argument_count;
static char **arguments;
static uint64_t sequence,context_key;
static SdkStats stats;

uintptr_t sdk_do_method_a(void *object,void *message) {
 if(!object || !message)return 0;
 return (uintptr_t)CALLHOOKPKT((struct Hook *)OCLASS((Object *)object),object,message);
}
uintptr_t sdk_do_super_method_a(void *class_pointer,void *object,void *message) {
 Class *class=(Class *)class_pointer;
 if(!class || !class->cl_Super || !object || !message)return 0;
 return (uintptr_t)CALLHOOKPKT((struct Hook *)class->cl_Super,object,message);
}
uintptr_t sdk_coerce_method_a(void *class_pointer,void *object,void *message) {
 if(!class_pointer || !object || !message)return 0;
 return (uintptr_t)CALLHOOKPKT((struct Hook *)class_pointer,object,message);
}
/* Default production observer: independent debugger can observe depth directly. */
volatile uint64_t ami_sdk_diagnostic_depth;
static uint64_t next_token(unsigned kind,size_t slot) {
 if (test_hit(9)) return 0;
 if (sequence >= SEQUENCE_LIMIT) return 0;
 return ((uint64_t)kind<<56)|((++sequence)<<SLOT_BITS)|(slot+1);
}
static int refuse(SdkError *e,int kind,int64_t native) {if(e){e->kind=kind;e->native=native;}++stats.refusals;return -1;}
static int clear_error(SdkError *e) {if(e){e->kind=0;e->native=0;}return 0;}
#ifdef AMI_RUST_ABI11
__attribute__((noinline))
#endif
static struct Task *current_task(void) {return FindTask(NULL);}
static int owner_is_current(void) {return owner && current_task()==owner;}
static int own(uint64_t key,SdkError *e) {
 clear_error(e);
 if (!active || closing || key!=context_key || !owner_is_current()) return refuse(e,4,0);
 return 0;
}
static int index_of(uint64_t token,unsigned kind,size_t cap) {
 size_t slot=(size_t)(token&SLOT_LIMIT);
 if (!token || (token>>56)!=kind || !slot || slot>cap) return -1;
 return (int)(slot-1);
}
static void *registry_alloc(size_t size) {
 if(!registry_pool || test_hit(15))return NULL;
 void *record=AllocPooled(registry_pool,size);
 if(record)memset(record,0,size);
 return record;
}
static void registry_free(void *record,size_t size) {if(record)FreePooled(registry_pool,record,size);}
static void *record_find(const struct Registry *registry,uint64_t token,unsigned kind) {
 int i=index_of(token,kind,registry->capacity);
 if(i<0 || !registry->items[i] || *(uint64_t *)registry->items[i]!=token)return NULL;
 return registry->items[i];
}
/* Reserves a zeroed record carrying a fresh token. Table growth, record
   allocation and token exhaustion all refuse without changing the registry. */
static void *record_new(struct Registry *registry,unsigned kind,size_t size,SdkError *e) {
 if(registry->count>=slot_limit){refuse(e,3,(int64_t)slot_limit);return NULL;}
 size_t i=0;
 while(i<registry->capacity && registry->items[i])++i;
 if(i==registry->capacity){
  size_t grown=registry->capacity?registry->capacity*2:8;
  if(grown>SLOT_LIMIT)grown=(size_t)SLOT_LIMIT;
  void **items=(void **)registry_alloc(grown*sizeof(void *));
  if(!items){refuse(e,1,ERROR_NO_FREE_STORE);return NULL;}
  for(size_t k=0;k<registry->capacity;k++)items[k]=registry->items[k];
  registry_free(registry->items,registry->capacity*sizeof(void *));
  registry->items=items;registry->capacity=grown;
 }
 uint64_t token=next_token(kind,i);if(!token){refuse(e,3,0);return NULL;}
 void *record=registry_alloc(size);if(!record){refuse(e,1,ERROR_NO_FREE_STORE);return NULL;}
 *(uint64_t *)record=token;registry->items[i]=record;++registry->count;return record;
}
#ifdef AMI_SDK_TESTING
/* Qualification control: a small token space makes Limit exhaustion testable
   without exhausting memory. Zero restores the production value. */
void sdk_test_slot_limit(uint64_t limit) {slot_limit=limit && limit<SLOT_LIMIT?limit:SLOT_LIMIT;}
#endif
static void record_release(struct Registry *registry,void *record,size_t size) {
 size_t slot=(size_t)(*(uint64_t *)record&SLOT_LIMIT);
 registry->items[slot-1]=NULL;--registry->count;registry_free(record,size);
}
static int byte_name(const uint8_t *p) {
 if (!p) return 0;
 for(size_t i=0;i<128;i++)if(!p[i])return 1;
 return 0;
}
static int argument_gate(int argc,char **argv) {
 if(argc<=0 || argc>32 || !argv)return 10;
 size_t bytes=0;
 for(int i=0;i<argc;i++){
  if(!argv[i])return 10;
  size_t n=0;while(n<4096 && argv[i][n])++n;
  if(n==4096 || bytes>4096-(n+1))return 10;
  bytes+=n+1;
 }
 return 0;
}
int sdk_begin(int argc,char **argv) {
 int invalid=argument_gate(argc,argv);if(invalid)return invalid;
 if(initialized || active || closing || !SysBase || !DOSBase)return 20;
 if(!compatible_exec(&SysBase->LibNode) || !compatible_dos(&DOSBase->dl_lib))return 20;
 initialized=1;owner=current_task();if(!owner)return 20;
 mandatory_dos=test_hit(13)?NULL:OpenLibrary((CONST_STRPTR)"dos.library",0);if(!mandatory_dos){owner=NULL;return 20;}
 argument_count=argc;arguments=argv;context_key=next_token(0x41,0);
 if(!context_key){CloseLibrary(mandatory_dos);mandatory_dos=NULL;owner=NULL;return 20;}
 registry_pool=CreatePool(MEMF_ANY,8192,2048);
 if(!registry_pool){CloseLibrary(mandatory_dos);mandatory_dos=NULL;owner=NULL;context_key=0;return 20;}
 claimed=0;active=1;return 0;
}
uint64_t sdk_context(void) {return active && !closing && owner_is_current()?context_key:0;}
uint64_t sdk_claim_context(void) {uint64_t key=sdk_context();if(!key||claimed)return 0;claimed=1;return key;}
size_t sdk_arg_count(uint64_t key) {return own(key,NULL)==0?(size_t)argument_count:0;}
const uint8_t *sdk_arg(uint64_t key,size_t i,size_t *length) {
 if(own(key,NULL)||!length||i>=(size_t)argument_count)return NULL;
 const uint8_t *p=(const uint8_t *)arguments[i];*length=0;while(p[*length])++*length;return p;
}
void *sdk_alloc(size_t size,size_t align) {
 AmiSdkAllocationLayout layout;size_t next_charge;
 if(!active || closing || !owner_is_current() || ami_sdk_diagnostic_depth ||
    !ami_sdk_allocation_layout(size,align,sizeof(struct Block),&layout) ||
    !ami_sdk_allocation_add_charge(stats.backing_charge,layout.charge,&next_charge)){++stats.refusals;return NULL;}
 if(test_hit(9)){++stats.refusals;return NULL;}
 struct Block *b=(struct Block *)AllocMem(layout.total,MEMF_ANY);if(!b){++stats.refusals;return NULL;}
 uintptr_t user_address;
 if(!ami_sdk_allocation_user_address((uintptr_t)b,&layout,&user_address)){
  FreeMem(b,layout.total);++stats.refusals;return NULL;
 }
 b->user=(void *)user_address;
 b->size=size;b->align=align;b->total=layout.total;b->charge=layout.charge;b->prev=NULL;b->next=blocks;
 if(blocks)blocks->prev=b;blocks=b;
 ++stats.blocks;stats.backing_charge=next_charge;if(stats.backing_charge>stats.peak_charge)stats.peak_charge=stats.backing_charge;
 return b->user;
}
void sdk_dealloc(void *p,size_t size,size_t align) {
 if(!active || closing || !owner_is_current()){++stats.refusals;return;}
 struct Block *b=blocks;while(b && b->user!=p)b=b->next;
 if(!b || b->size!=size || b->align!=align){++stats.refusals;return;}
 if(b->prev)b->prev->next=b->next;else blocks=b->next;
 if(b->next)b->next->prev=b->prev;
 size_t total=b->total;--stats.blocks;stats.backing_charge-=b->charge;FreeMem(b,total);
}
void sdk_diagnostic(const uint8_t *label,size_t length,uint64_t code) {
 uint8_t buffer[256];size_t n=0;
 ++ami_sdk_diagnostic_depth;
#ifdef AMI_SDK_TESTING
 if(test_hit(14) || (secondary_on_diagnostic && closing)){secondary_on_diagnostic=0;sdk_fatal(14);}
 /* Positive detection controls allocate inside the actual SDK diagnostic
    window. The pool is created before entry, so pool use cannot hide here. */
 uint32_t probe=diagnostic_probe;diagnostic_probe=0;
 if(probe)ami_test_measurement_expected(probe);
 if(probe==1){APTR p=AllocMem(1,MEMF_ANY);if(p)FreeMem(p,1);}
 if(probe==2){void *p=malloc(1);if(p){*(volatile uint8_t *)p=0x61;__asm__ volatile(""::"r"(p):"memory");free(p);}}
 if(probe==3 && diagnostic_pool){APTR p=AllocPooled(diagnostic_pool,1);if(p)FreePooled(diagnostic_pool,p,1);}
 if(probe)ami_test_measurement_expected(0);
#endif
 if(label){if(length>230)length=230;for(size_t i=0;i<length;i++)buffer[n++]=label[i];}
 buffer[n++]=' ';uint8_t digits[20];size_t k=0;
 do{digits[k++]=(uint8_t)('0'+code%10);code/=10;}while(code && k<20);
 while(k)buffer[n++]=digits[--k];buffer[n++]='\n';
 for(size_t i=0;i<n;i++)RawPutChar(buffer[i]);
 --ami_sdk_diagnostic_depth;
}
SdkStats sdk_stats(void) {return stats;}
uint64_t sdk_library_open(uint64_t key,const uint8_t *name,uint16_t version,SdkError *e) {
 if(own(key,e))return 0;if(!byte_name(name)){refuse(e,2,0);return 0;}
 struct LibSlot *slot=(struct LibSlot *)record_new(&libraries,KIND_LIBRARY,sizeof(*slot),e);if(!slot)return 0;
 struct Library *l=OpenLibrary((CONST_STRPTR)name,version);
 if(!l){record_release(&libraries,slot,sizeof(*slot));refuse(e,1,0);return 0;}
 slot->handle=l;++stats.libraries;return slot->token;
}
void *sdk_library_base(uint64_t key,uint64_t token) {
 if(own(key,NULL))return NULL;struct LibSlot *slot=(struct LibSlot *)record_find(&libraries,token,KIND_LIBRARY);
 if(!slot || !slot->handle){refuse(NULL,5,0);return NULL;}
 return slot->handle;
}
int sdk_library_close(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct LibSlot *slot=(struct LibSlot *)record_find(&libraries,token,KIND_LIBRARY);
 if(!slot || !slot->handle)return refuse(e,5,0);
 struct Library *l=slot->handle;record_release(&libraries,slot,sizeof(*slot));--stats.libraries;CloseLibrary(l);return 0;
}
uint64_t sdk_file_open(uint64_t key,const uint8_t *path,int32_t mode,SdkError *e) {
 if(own(key,e))return 0;if(!byte_name(path) || mode<0 || mode>2){refuse(e,2,0);return 0;}
 struct FileSlot *slot=(struct FileSlot *)record_new(&files,KIND_FILE,sizeof(*slot),e);if(!slot)return 0;
 BPTR f=Open((CONST_STRPTR)path,mode==0?MODE_OLDFILE:mode==1?MODE_NEWFILE:MODE_READWRITE);
 if(!f){SIPTR error=IoErr();record_release(&files,slot,sizeof(*slot));refuse(e,1,error);return 0;}
 slot->handle=f;++stats.files;return slot->token;
}
int sdk_file_close(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct FileSlot *slot=(struct FileSlot *)record_find(&files,token,KIND_FILE);
 if(!slot || !slot->handle)return refuse(e,5,0);
 BPTR f=slot->handle;record_release(&files,slot,sizeof(*slot));--stats.files;
 BOOL ok=Close(f);if(!ok){SIPTR error=IoErr();return refuse(e,1,error);}return 0;
}
uint64_t sdk_stdout(uint64_t key) {return own(key,NULL)==0?OUTPUT_TOKEN:0;}
uint64_t sdk_stderr(uint64_t key) {
 /* Only a DOS Process has pr_CES/pr_COS. Never cast an arbitrary Exec task. */
 return own(key,NULL)==0 && owner->tc_Node.ln_Type==NT_PROCESS?ERROR_OUTPUT_TOKEN:0;
}
int64_t sdk_file_io(uint64_t key,uint64_t token,uint8_t *buffer,size_t n,int32_t writing,SdkError *e) {
 if(own(key,e))return -1;
 if(n>65536 || (n && !buffer) || (writing!=0 && writing!=1))return refuse(e,2,0);
 BPTR f;
 if(token==OUTPUT_TOKEN){if(!writing)return refuse(e,5,0);f=Output();if(!f)return refuse(e,1,0);}
 else if(token==ERROR_OUTPUT_TOKEN){
  if(!writing || owner->tc_Node.ln_Type!=NT_PROCESS)return refuse(e,5,0);
  /* Process-owned borrowed streams: resolve on each write and never close. */
  struct Process *process=(struct Process *)owner;
  f=process->pr_CES?process->pr_CES:process->pr_COS;
  if(!f)return refuse(e,1,0);
 }
 else{struct FileSlot *slot=(struct FileSlot *)record_find(&files,token,KIND_FILE);if(!slot)return refuse(e,5,0);f=slot->handle;}
 LONG result=writing?Write(f,buffer,(LONG)n):Read(f,buffer,(LONG)n);
 if(result<0){SIPTR error=IoErr();return refuse(e,1,error);}return (int64_t)result;
}
#ifdef AMI_SDK_TESTING
#include "test-stderr-controls.h"
#endif
static struct SignalSlot *signal_find(uint64_t token) {
 int i=index_of(token,KIND_SIGNAL,SIGNAL_SLOTS);
 return i>=0 && signals[i].token==token && !signals[i].port_owned && signals[i].bit>=0?&signals[i]:NULL;
}
uint64_t sdk_signal_new(uint64_t key,SdkError *e) {
 if(own(key,e))return 0;size_t i=0;while(i<SIGNAL_SLOTS && signals[i].token)++i;
 /* Exec offers at most 32 signal bits per task; the slot table cannot outgrow them. */
 if(i==SIGNAL_SLOTS){refuse(e,3,SIGNAL_SLOTS);return 0;}uint64_t token=next_token(KIND_SIGNAL,i);if(!token){refuse(e,3,0);return 0;}
 signals[i]=(struct SignalSlot){token,-1,0};
 BYTE bit=AllocSignal(-1);if(bit<0){signals[i]=(struct SignalSlot){0};refuse(e,1,0);return 0;}
 signals[i]=(struct SignalSlot){token,bit,0};++stats.signals;return token;
}
int sdk_signal_drop(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct SignalSlot *slot=signal_find(token);
 if(!slot)return refuse(e,5,0);
 int bit=slot->bit;*slot=(struct SignalSlot){0};--stats.signals;SetSignal(0,1UL<<bit);FreeSignal(bit);return 0;
}
int sdk_signal_post(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct SignalSlot *slot=signal_find(token);
 if(!slot)return refuse(e,5,0);
 Signal(owner,1UL<<slot->bit);return 0;
}
int sdk_signal_wait(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct SignalSlot *slot=signal_find(token);
 if(!slot)return refuse(e,5,0);
 Wait(1UL<<slot->bit);return 0;
}
int sdk_signal_wait_mask(uint64_t key,uint32_t mask,uint32_t *received,SdkError *e) {
 if(own(key,e))return -1;
 if(!mask || !received)return refuse(e,2,0);
 *received=Wait(mask);return 0;
}
static struct PortSlot *port_create(SdkError *e) {
 size_t s=0;while(s<SIGNAL_SLOTS && signals[s].token)++s;
 if(s==SIGNAL_SLOTS){refuse(e,3,SIGNAL_SLOTS);return NULL;}
 struct PortSlot *slot=(struct PortSlot *)record_new(&ports,KIND_PORT,sizeof(*slot),e);if(!slot)return NULL;
 uint64_t sig=next_token(KIND_SIGNAL,s);
 if(!sig){record_release(&ports,slot,sizeof(*slot));refuse(e,3,0);return NULL;}
 slot->signal_slot=(int)s;signals[s]=(struct SignalSlot){sig,-1,1};
 struct MsgPort *port=CreateMsgPort();
 if(!port){signals[s]=(struct SignalSlot){0};record_release(&ports,slot,sizeof(*slot));refuse(e,1,0);return NULL;}
 slot->handle=port;signals[s]=(struct SignalSlot){sig,port->mp_SigBit,1};++stats.ports;++stats.signals;return slot;
}
uint64_t sdk_port_new(uint64_t key,SdkError *e) {
 if(own(key,e))return 0;struct PortSlot *slot=port_create(e);return slot?slot->token:0;
}
static struct MessageSlot *message_find(uint64_t token) {return (struct MessageSlot *)record_find(&messages,token,KIND_MESSAGE);}
static struct PortSlot *port_find(uint64_t token) {return (struct PortSlot *)record_find(&ports,token,KIND_PORT);}
static void detach_message(struct MessageSlot *m) {
 if(m->queued){Remove(&m->native.mn_Node);m->queued=0;m->queued_port=0;}
}
static void clear_port(struct PortSlot *slot) {
 uint64_t token=slot->token;struct MsgPort *port=slot->handle;int s=slot->signal_slot;
 for(size_t n=0;n<messages.capacity;n++){
  struct MessageSlot *m=(struct MessageSlot *)messages.items[n];if(!m)continue;
  if(m->queued_port==token){detach_message(m);m->state=0;m->reply_port=0;m->native.mn_ReplyPort=NULL;}
  if(m->reply_port==token){m->reply_port=0;m->native.mn_ReplyPort=NULL;if(m->state==2)m->state=0;}
 }
 record_release(&ports,slot,sizeof(*slot));signals[s]=(struct SignalSlot){0};--stats.ports;--stats.signals;
 SetSignal(0,1UL<<port->mp_SigBit);DeleteMsgPort(port);
}
int sdk_port_drop(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct PortSlot *slot=port_find(token);if(!slot || !slot->handle)return refuse(e,5,0);clear_port(slot);return 0;
}
uint64_t sdk_message_new(uint64_t key,const uint8_t *data,size_t n,SdkError *e) {
 if(own(key,e))return 0;if(n>256 || (n && !data)){refuse(e,2,0);return 0;}
 struct MessageSlot *m=(struct MessageSlot *)record_new(&messages,KIND_MESSAGE,sizeof(*m),e);if(!m)return 0;
 m->size=n;m->native.mn_Length=sizeof(m->native)+256;
 for(size_t k=0;k<n;k++)m->payload[k]=data[k];++stats.messages;return m->token;
}
int sdk_message_drop(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct MessageSlot *m=message_find(token);if(!m)return refuse(e,5,0);detach_message(m);record_release(&messages,m,sizeof(*m));--stats.messages;return 0;
}
int sdk_message_copy(uint64_t key,uint64_t token,uint8_t *out,size_t cap,SdkError *e) {
 if(own(key,e))return -1;struct MessageSlot *m=message_find(token);if(!m || m->queued)return refuse(e,5,0);
 if(cap<m->size || (m->size && !out))return refuse(e,2,0);
 for(size_t k=0;k<m->size;k++)out[k]=m->payload[k];return (int)m->size;
}
int sdk_port_put(uint64_t key,uint64_t port_token,uint64_t message_token,uint64_t reply_token,SdkError *e) {
 if(own(key,e))return -1;struct PortSlot *p=port_find(port_token),*r=port_find(reply_token);struct MessageSlot *msg=message_find(message_token);
 if(!p || !r || !msg || msg->state!=0)return refuse(e,5,0);
 msg->reply_port=reply_token;msg->native.mn_ReplyPort=r->handle;msg->queued=1;msg->state=1;msg->queued_port=port_token;PutMsg(p->handle,&msg->native);return 0;
}
int sdk_port_receive(uint64_t key,uint64_t port_token,uint64_t message_token,SdkError *e) {
 if(own(key,e))return -1;struct PortSlot *p=port_find(port_token);struct MessageSlot *msg=message_find(message_token);
 if(!p || !msg)return refuse(e,5,0);
 struct MsgPort *port=p->handle;
 struct Node *head=port->mp_MsgList.lh_Head;
 if(head==(struct Node *)&port->mp_MsgList.lh_Tail)return 0;
 if(head!=&msg->native.mn_Node || !msg->queued || msg->queued_port!=port_token)return refuse(e,5,0);
 struct Message *got=GetMsg(port);if(got!=&msg->native)return refuse(e,5,0);
 msg->queued=0;msg->queued_port=0;msg->state=msg->state==1 && msg->reply_port?2:0;return 1;
}
int sdk_message_reply(uint64_t key,uint64_t message_token,SdkError *e) {
 if(own(key,e))return -1;struct MessageSlot *msg=message_find(message_token);if(!msg)return refuse(e,5,0);
 struct PortSlot *p=port_find(msg->reply_port);
 if(msg->state!=2 || msg->queued || !p || msg->native.mn_ReplyPort!=p->handle)return refuse(e,5,0);
 msg->queued=1;msg->state=3;msg->queued_port=msg->reply_port;ReplyMsg(&msg->native);return 0;
}

#define IO_OPEN_SIZE (sizeof(struct IOStdReq)>sizeof(struct timerequest)?sizeof(struct IOStdReq):sizeof(struct timerequest))
static struct DeviceSlot *device_find(uint64_t token) {return (struct DeviceSlot *)record_find(&devices,token,KIND_DEVICE);}
static struct IoSlot *io_find(uint64_t token) {return (struct IoSlot *)record_find(&requests,token,KIND_REQUEST);}
static void *io_alloc(size_t size) {return AllocMem(size,MEMF_PUBLIC|MEMF_CLEAR);}
uint64_t sdk_device_open(uint64_t key,const uint8_t *name,uint32_t unit,uint32_t flags,SdkError *e) {
 if(own(key,e))return 0;if(!byte_name(name)){refuse(e,2,0);return 0;}
 struct DeviceSlot *dev=(struct DeviceSlot *)record_new(&devices,KIND_DEVICE,sizeof(*dev),e);if(!dev)return 0;
 struct PortSlot *port=port_create(e);if(!port){record_release(&devices,dev,sizeof(*dev));return 0;}
 struct IORequest *open=(struct IORequest *)io_alloc(IO_OPEN_SIZE);
 if(!open){clear_port(port);record_release(&devices,dev,sizeof(*dev));refuse(e,1,ERROR_NO_FREE_STORE);return 0;}
 open->io_Message.mn_Node.ln_Type=NT_REPLYMSG;open->io_Message.mn_ReplyPort=port->handle;open->io_Message.mn_Length=IO_OPEN_SIZE;
 BYTE error=OpenDevice((CONST_STRPTR)name,unit,open,flags);
 if(error){FreeMem(open,IO_OPEN_SIZE);clear_port(port);record_release(&devices,dev,sizeof(*dev));refuse(e,1,error);return 0;}
 dev->open=open;dev->size=IO_OPEN_SIZE;dev->port=port->token;++stats.devices;return dev->token;
}
static void device_release(struct DeviceSlot *dev) {
 struct IORequest *open=dev->open;size_t size=dev->size;uint64_t port_token=dev->port;
 record_release(&devices,dev,sizeof(*dev));--stats.devices;
 if(open){CloseDevice(open);FreeMem(open,size);}
 struct PortSlot *port=port_find(port_token);if(port && port->handle)clear_port(port);
}
int sdk_device_close(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct DeviceSlot *dev=device_find(token);if(!dev || !dev->open || dev->requests)return refuse(e,5,0);
 device_release(dev);return 0;
}
uint32_t sdk_device_signal_mask(uint64_t key,uint64_t token) {
 if(own(key,NULL))return 0;struct DeviceSlot *dev=device_find(token);if(!dev)return 0;
 struct PortSlot *port=port_find(dev->port);return port && port->handle?1UL<<port->handle->mp_SigBit:0;
}
uint64_t sdk_io_new(uint64_t key,uint64_t device,int32_t kind,size_t capacity,SdkError *e) {
 if(own(key,e))return 0;struct DeviceSlot *dev=device_find(device);if(!dev || !dev->open){refuse(e,5,0);return 0;}
 if((kind!=IO_KIND_STANDARD && kind!=IO_KIND_TIMER) || capacity>IO_MAX_DATA || (kind==IO_KIND_TIMER && capacity)){refuse(e,2,0);return 0;}
 struct PortSlot *port=port_find(dev->port);if(!port || !port->handle){refuse(e,5,0);return 0;}
 struct IoSlot *slot=(struct IoSlot *)record_new(&requests,KIND_REQUEST,sizeof(*slot),e);if(!slot)return 0;
 size_t size=kind==IO_KIND_TIMER?sizeof(struct timerequest):sizeof(struct IOStdReq);
 struct IORequest *request=(struct IORequest *)io_alloc(size);
 uint8_t *buffer=capacity && request?(uint8_t *)io_alloc(capacity):NULL;
 if(!request || (capacity && !buffer)){
  if(buffer)FreeMem(buffer,capacity);if(request)FreeMem(request,size);
  record_release(&requests,slot,sizeof(*slot));refuse(e,1,ERROR_NO_FREE_STORE);return 0;
 }
 request->io_Message.mn_Node.ln_Type=NT_REPLYMSG;request->io_Message.mn_ReplyPort=port->handle;request->io_Message.mn_Length=size;
 request->io_Device=dev->open->io_Device;request->io_Unit=dev->open->io_Unit;
 slot->device=device;slot->request=request;slot->size=size;slot->buffer=buffer;slot->capacity=capacity;slot->kind=kind;slot->state=IO_IDLE;
 ++dev->requests;++stats.requests;return slot->token;
}
/* Retires the record first, then aborts and reclaims a pending request. */
static void io_release(struct IoSlot *slot) {
 struct IORequest *request=slot->request;size_t size=slot->size,capacity=slot->capacity;uint8_t *buffer=slot->buffer;
 int pending=slot->state==IO_PENDING;struct DeviceSlot *dev=device_find(slot->device);
 record_release(&requests,slot,sizeof(*slot));--stats.requests;if(dev && dev->requests)--dev->requests;
 if(pending){AbortIO(request);WaitIO(request);}
 FreeMem(request,size);if(buffer)FreeMem(buffer,capacity);
}
int sdk_io_drop(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot)return refuse(e,5,0);
 io_release(slot);return 0;
}
int sdk_io_prepare(uint64_t key,uint64_t token,uint32_t command,uint32_t flags,size_t length,uint32_t offset,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE)return refuse(e,5,0);
 if(command>0xffff || flags>0xff || (slot->kind==IO_KIND_TIMER && (length || offset)) || length>slot->capacity)return refuse(e,2,0);
 slot->request->io_Command=(UWORD)command;slot->request->io_Flags=(UBYTE)flags;slot->request->io_Error=0;
 if(slot->kind==IO_KIND_STANDARD){
  struct IOStdReq *standard=(struct IOStdReq *)slot->request;
  standard->io_Data=slot->buffer;standard->io_Length=(ULONG)length;standard->io_Offset=offset;standard->io_Actual=0;
 }
 return 0;
}
int sdk_io_write(uint64_t key,uint64_t token,const uint8_t *data,size_t n,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE || slot->kind!=IO_KIND_STANDARD)return refuse(e,5,0);
 if(n>slot->capacity || (n && !data))return refuse(e,2,0);
 for(size_t k=0;k<n;k++)slot->buffer[k]=data[k];return 0;
}
int64_t sdk_io_read(uint64_t key,uint64_t token,uint8_t *out,size_t cap,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE || slot->kind!=IO_KIND_STANDARD)return refuse(e,5,0);
 size_t n=((struct IOStdReq *)slot->request)->io_Actual;if(n>slot->capacity)n=slot->capacity;
 if(cap<n || (n && !out))return refuse(e,2,0);
 for(size_t k=0;k<n;k++)out[k]=slot->buffer[k];return (int64_t)n;
}
int sdk_io_set_time(uint64_t key,uint64_t token,uint32_t seconds,uint32_t micros,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE || slot->kind!=IO_KIND_TIMER)return refuse(e,5,0);
 if(micros>=1000000UL)return refuse(e,2,0);
 struct timerequest *timer=(struct timerequest *)slot->request;timer->tr_time.tv_secs=seconds;timer->tr_time.tv_micro=micros;return 0;
}
int sdk_io_time(uint64_t key,uint64_t token,uint32_t *seconds,uint32_t *micros,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE || slot->kind!=IO_KIND_TIMER)return refuse(e,5,0);
 if(!seconds || !micros)return refuse(e,2,0);
 struct timerequest *timer=(struct timerequest *)slot->request;*seconds=timer->tr_time.tv_secs;*micros=timer->tr_time.tv_micro;return 0;
}
int sdk_io_result(uint64_t key,uint64_t token,int32_t *device_error,uint32_t *actual,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE)return refuse(e,5,0);
 if(!device_error || !actual)return refuse(e,2,0);
 *device_error=(int32_t)(BYTE)slot->request->io_Error;
 *actual=slot->kind==IO_KIND_STANDARD?((struct IOStdReq *)slot->request)->io_Actual:0;return 0;
}
int sdk_io_do(uint64_t key,uint64_t token,int32_t *device_error,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE)return refuse(e,5,0);
 if(!device_error)return refuse(e,2,0);
 *device_error=(int32_t)(BYTE)DoIO(slot->request);return 0;
}
int sdk_io_send(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_IDLE)return refuse(e,5,0);
 slot->state=IO_PENDING;SendIO(slot->request);return 0;
}
int sdk_io_check(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_PENDING)return refuse(e,5,0);
 return CheckIO(slot->request)?1:0;
}
int sdk_io_wait(uint64_t key,uint64_t token,int32_t *device_error,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_PENDING)return refuse(e,5,0);
 if(!device_error)return refuse(e,2,0);
 *device_error=(int32_t)(BYTE)WaitIO(slot->request);slot->state=IO_IDLE;return 0;
}
int sdk_io_abort(uint64_t key,uint64_t token,SdkError *e) {
 if(own(key,e))return -1;struct IoSlot *slot=io_find(token);if(!slot || slot->state!=IO_PENDING)return refuse(e,5,0);
 AbortIO(slot->request);return 0;
}
int sdk_callback(uint64_t key,uint64_t (*callback)(void *,uint64_t),void *data,uint64_t value,uint64_t *out,SdkError *e) {
 if(own(key,e))return -1;if(callback_active || !callback || !data || !out)return refuse(e,5,0);
 callback_active=1;*out=callback(data,value);callback_active=0;return 0;
}
#ifdef AMI_SDK_TESTING
static uint64_t counter_callback(void *p,uint64_t value){++*(unsigned *)p;return value;}
static int test_report_ledgers(void) {
 sdk_diagnostic((const uint8_t *)"[m1-ledger] blocks",18,stats.blocks);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] backing",19,stats.backing_charge);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] files",17,stats.files);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] libraries",21,stats.libraries);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] ports",17,stats.ports);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] signals",19,stats.signals);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] messages",20,stats.messages);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] devices",19,stats.devices);
 sdk_diagnostic((const uint8_t *)"[m1-ledger] requests",20,stats.requests);
 sdk_diagnostic((const uint8_t *)"[m1-native] live",16,backend_live());
 sdk_diagnostic((const uint8_t *)"[m1-native] errors",18,backend_errors);
 sdk_diagnostic((const uint8_t *)"[m1-native] signal-mask-delta",29,(uint64_t)(current_task()->tc_SigAlloc^initial_signal_mask));
 return backend_live()||backend_errors||current_task()->tc_SigAlloc!=initial_signal_mask?20:0;
}
#endif
static int cleanup_remaining(void) {
#ifdef AMI_SDK_TESTING
 test_stderr_restore();
 ami_test_phase(4);
#endif
 closing=1;callback_active=1;cleanup_error=0;cleanup_resume_ready=1;
 /* Native releases retire their registry record first. A fatal diagnostic
    during a release resumes this C drain iteratively, with no Rust frame or
    recursive teardown retry. Locals are recreated after the setjmp return. */
 if(setjmp(cleanup_resume)){cleanup_error=20;ami_sdk_diagnostic_depth=0;}
 for(size_t i=0;i<requests.capacity;i++){struct IoSlot *slot=(struct IoSlot *)requests.items[i];if(slot)io_release(slot);}
 for(size_t i=0;i<devices.capacity;i++){struct DeviceSlot *dev=(struct DeviceSlot *)devices.items[i];if(dev)device_release(dev);}
 for(size_t i=0;i<messages.capacity;i++){struct MessageSlot *m=(struct MessageSlot *)messages.items[i];if(m){detach_message(m);record_release(&messages,m,sizeof(*m));--stats.messages;}}
 for(size_t i=0;i<files.capacity;i++){struct FileSlot *slot=(struct FileSlot *)files.items[i];if(!slot)continue;BPTR f=slot->handle;record_release(&files,slot,sizeof(*slot));if(!f)continue;--stats.files;if(!Close(f)){SIPTR error=IoErr();sdk_diagnostic((const uint8_t *)"close",5,(uint64_t)error);cleanup_error=20;}}
 for(size_t i=0;i<libraries.capacity;i++){struct LibSlot *slot=(struct LibSlot *)libraries.items[i];if(!slot)continue;struct Library *l=slot->handle;record_release(&libraries,slot,sizeof(*slot));if(l){--stats.libraries;CloseLibrary(l);}}
 for(size_t i=0;i<ports.capacity;i++){struct PortSlot *slot=(struct PortSlot *)ports.items[i];if(!slot)continue;if(slot->handle)clear_port(slot);else{int s=slot->signal_slot;record_release(&ports,slot,sizeof(*slot));signals[s]=(struct SignalSlot){0};}}
 for(size_t i=0;i<SIGNAL_SLOTS;i++)if(signals[i].token){int bit=signals[i].bit;signals[i]=(struct SignalSlot){0};if(bit>=0){--stats.signals;SetSignal(0,1UL<<bit);FreeSignal(bit);}}
 while(blocks){struct Block *b=blocks;blocks=b->next;size_t total=b->total;--stats.blocks;stats.backing_charge-=b->charge;FreeMem(b,total);}
 if(mandatory_dos){struct Library *l=mandatory_dos;mandatory_dos=NULL;CloseLibrary(l);}
 if(registry_pool){
  /* The tables are the pool's last users; the pool is retired with them. */
  APTR pool=registry_pool;registry_pool=NULL;
  files=(struct Registry){0};libraries=(struct Registry){0};ports=(struct Registry){0};messages=(struct Registry){0};devices=(struct Registry){0};requests=(struct Registry){0};
  DeletePool(pool);
 }
#ifdef AMI_SDK_TESTING
 if(diagnostic_pool){APTR pool=diagnostic_pool;diagnostic_pool=NULL;DeletePool(pool);}
#endif
#ifdef AMI_SDK_TESTING
 if(test_report_ledgers())cleanup_error=20;
#endif
 uint64_t expired_key=context_key;
 arguments=NULL;argument_count=0;context_key=0;active=0;closing=0;owner=NULL;cleanup_resume_ready=0;
#ifdef AMI_SDK_TESTING
 SdkError expired_error;uint64_t expired_out=0;unsigned expired_calls=0;
 int expired_ok=sdk_callback(expired_key,counter_callback,&expired_calls,0,&expired_out,&expired_error)==-1 && expired_error.kind==4 && !expired_calls;
 sdk_diagnostic((const uint8_t *)"[m1-counter] expired",20,expired_ok);
 if(!expired_ok)cleanup_error=20;
#else
 (void)expired_key;
#endif
 return cleanup_error;
}
int sdk_end(void) {
 if(!active || closing || !owner_is_current())return 20;
 return cleanup_remaining();
}
_Noreturn void sdk_fatal(uint64_t reason) {
 if(closing){
  fatal_started=1;
  /* Fixed secondary record, inside the existing diagnostic window. It cannot
     re-enter the formatter or a registered Rust callback. */
  static const uint8_t text[]="ami-rust fatal during cleanup\n";
  for(size_t i=0;i<sizeof(text)-1;i++)RawPutChar(text[i]);
  if(cleanup_resume_ready && owner_is_current())longjmp(cleanup_resume,1);
  _Exit(20);
 }
 if(!fatal_started){fatal_started=1;sdk_diagnostic((const uint8_t *)"ami-rust fatal",14,reason);}
 else{
  static const uint8_t text[]="ami-rust nested fatal\n";
  for(size_t i=0;i<sizeof(text)-1;i++)RawPutChar(text[i]);
  /* The original formatter frame is abandoned by this nonreturning path. */
  ami_sdk_diagnostic_depth=0;
 }
 if(active && owner_is_current()){int result=cleanup_remaining();(void)result;}
 /* Pinned _Exit skips user exit hooks and goes to native startup teardown. */
 _Exit(20);
}
extern int rust_sdk_main(void);
int main(int argc,char **argv) {
#ifdef AMI_SDK_TESTING
 if(!(argc>1 && !strcmp(argv[1],"missing-window")))ami_test_bind_diagnostics(&ami_sdk_diagnostic_depth);
 initial_signal_mask=current_task()->tc_SigAlloc;
 if(argc>1 && (!strcmp(argv[1],"startup-fail")||!strcmp(argv[1],"fault13")))sdk_test_fault(13,1);
 if(argc>1 && !strcmp(argv[1],"startup-slot"))sdk_test_fault(9,1);
 if(argc>1 && !strcmp(argv[1],"diag-direct"))diagnostic_probe=1;
 if(argc>1 && !strcmp(argv[1],"diag-malloc"))diagnostic_probe=2;
 if(argc>1 && !strcmp(argv[1],"diag-pool"))diagnostic_probe=3;
#endif
 int result=sdk_begin(argc,argv);if(result){
#ifdef AMI_SDK_TESTING
 ami_test_phase(4);
 if(test_report_ledgers())return 20;
#endif
 return result;
 }
#ifdef AMI_SDK_TESTING
 if(diagnostic_probe==3){diagnostic_pool=CreatePool(MEMF_ANY,4096,1024);if(!diagnostic_pool)return 20;}
#endif
#ifdef AMI_SDK_TESTING
 ami_test_phase(3);
 if(diagnostic_probe)ami_test_measurement_expected(diagnostic_probe);
 /* Bounded qualification controls exercise the actual argument/owner/cap
    branches without creating a foreign task or exhausting global memory. */
 struct Library copied_header=SysBase->LibNode;
 int compatibility_ok=compatible_exec(&copied_header);
 copied_header.lib_Version=50;compatibility_ok=compatibility_ok && !compatible_exec(&copied_header);
 copied_header.lib_Version=51;copied_header.lib_NegSize=169*LIB_VECTSIZE-1;
 compatibility_ok=compatibility_ok && !compatible_exec(&copied_header);
 copied_header=DOSBase->dl_lib;compatibility_ok=compatibility_ok && compatible_dos(&copied_header);
 copied_header.lib_Version=49;compatibility_ok=compatibility_ok && !compatible_dos(&copied_header);
 copied_header.lib_Version=50;copied_header.lib_NegSize=77*LIB_VECTSIZE-1;
 compatibility_ok=compatibility_ok && !compatible_dos(&copied_header);
 sdk_diagnostic((const uint8_t *)"[m1-counter] compatibility",26,compatibility_ok);
 char argument_bytes[4097];char *argument_rows[33];
 memset(argument_bytes,'x',sizeof(argument_bytes));argument_bytes[4095]=0;
 for(size_t i=0;i<33;i++)argument_rows[i]=(char *)"";
 int argument_ok=argument_gate(32,argument_rows)==0 && argument_gate(33,argument_rows)==10;
 argument_rows[0]=argument_bytes;argument_ok=argument_ok && argument_gate(1,argument_rows)==0;
 argument_bytes[4095]='x';argument_bytes[4096]=0;argument_ok=argument_ok && argument_gate(1,argument_rows)==10;
 argument_rows[0]=NULL;argument_ok=argument_ok && argument_gate(1,argument_rows)==10;
 argument_rows[0]=argument_bytes;argument_rows[1]=(char *)"";
 argument_bytes[4094]=0;argument_ok=argument_ok && argument_gate(2,argument_rows)==0;
 argument_bytes[4094]='x';argument_bytes[4095]=0;argument_ok=argument_ok && argument_gate(2,argument_rows)==10;
 argument_bytes[127]=0;for(size_t i=0;i<32;i++)argument_rows[i]=argument_bytes;
 argument_ok=argument_ok && argument_gate(32,argument_rows)==0;
 argument_bytes[127]='x';argument_bytes[128]=0;argument_ok=argument_ok && argument_gate(32,argument_rows)==10;
 uint64_t saved_backend_errors=backend_errors;
 /* Checker copy only: no fake pointer is passed to an OS release. */
 backend_acquire(1,UINTPTR_MAX,64);
 int release_once=backend_release(1,UINTPTR_MAX,64);
 int duplicate_refused=!backend_release(1,UINTPTR_MAX,64) && backend_errors==saved_backend_errors+1;
 backend_errors=saved_backend_errors;
 int allocation_checkers_ok=release_once && duplicate_refused;
 sdk_diagnostic((const uint8_t *)"[m1-counter] allocation-checkers",32,allocation_checkers_ok);
 size_t before_charge=stats.backing_charge;uint64_t before_live=backend_live();
 stats.backing_charge=SIZE_MAX;void *overflow_probe=sdk_alloc(64,4096);
 int charge_overflow_ok=!overflow_probe && stats.backing_charge==SIZE_MAX && backend_live()==before_live;
 if(overflow_probe)sdk_dealloc(overflow_probe,64,4096);
 stats.backing_charge=before_charge;
 struct Task *saved_owner=owner;owner=(struct Task *)((uintptr_t)owner^1);
 SdkError owner_error;uint64_t owner_out=0;unsigned owner_calls=0;
 int owner_ok=sdk_callback(context_key,counter_callback,&owner_calls,0,&owner_out,&owner_error)==-1 && owner_error.kind==4 && !owner_calls && sdk_context()==0;
 owner=saved_owner;
 sdk_diagnostic((const uint8_t *)"[m1-counter] arguments",22,argument_ok);
 sdk_diagnostic((const uint8_t *)"[m1-counter] charge-overflow",sizeof("[m1-counter] charge-overflow")-1,charge_overflow_ok);
 sdk_diagnostic((const uint8_t *)"[m1-counter] task-owner",23,owner_ok);
 if(!argument_ok || !charge_overflow_ok || !owner_ok || !compatibility_ok || !allocation_checkers_ok){int closed=sdk_end();(void)closed;return 20;}
#ifndef AMI_RUST_ABI11
 /* The stack instrument belongs to the ABI-v1 entry, which checks the 128 KiB stack. */
 if(argc>1 && !strcmp(argv[1],"calibrate") && ami_stack_calibrate()){int failed_cleanup=sdk_end();(void)failed_cleanup;return 20;}
#endif
 if(argc>1 && !strcmp(argv[1],"cleanup-secondary")){sdk_test_fault(5,1);secondary_on_diagnostic=1;}
#endif
 result=rust_sdk_main();int closed=sdk_end();

 if(closed || fatal_started)return 20;
 return result==0||result==10||result==20?result:20;
}
