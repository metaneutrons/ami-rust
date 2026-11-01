/* Qualification-only fault controls. Never compiled into the source SDK recipe. */
#ifdef AMI_SDK_TESTING
#ifdef AMI_RUST_ABI11
/* ABI-v11 library calls must not be inlined into these wrappers. */
#define TEST_NOINLINE __attribute__((noinline))
#else
#define TEST_NOINLINE
#endif
/* Synthetic input for window tests: events are written to input.device, so a
   native test drives Intuition the way a keyboard and mouse would. */
#include <devices/inputevent.h>
#ifndef IND_ADDEVENT
#define IND_ADDEVENT (CMD_NONSTD+15)
#endif
static struct MsgPort *test_input_port;
static struct IOStdReq *test_input_io;
int sdk_test_input_open(void) {
 if(test_input_io)return 0;
 test_input_port=CreateMsgPort();if(!test_input_port)return -1;
 test_input_io=(struct IOStdReq *)CreateIORequest(test_input_port,sizeof(struct IOStdReq));
 if(!test_input_io){DeleteMsgPort(test_input_port);test_input_port=NULL;return -2;}
 if(OpenDevice((CONST_STRPTR)"input.device",0,(struct IORequest *)test_input_io,0)){
  DeleteIORequest((struct IORequest *)test_input_io);test_input_io=NULL;DeleteMsgPort(test_input_port);test_input_port=NULL;return -3;
 }
 return 0;
}
int sdk_test_input_send(uint32_t class_,uint32_t code,uint32_t qualifier,int32_t x,int32_t y) {
 if(!test_input_io)return -1;
 struct InputEvent event;memset(&event,0,sizeof(event));
 event.ie_Class=(UBYTE)class_;event.ie_Code=(UWORD)code;event.ie_Qualifier=(UWORD)qualifier;
 event.ie_X=(WORD)x;event.ie_Y=(WORD)y;
 test_input_io->io_Command=IND_ADDEVENT;test_input_io->io_Data=&event;test_input_io->io_Length=sizeof(event);
 return (int)DoIO((struct IORequest *)test_input_io);
}
void sdk_test_input_close(void) {
 if(!test_input_io)return;
 CloseDevice((struct IORequest *)test_input_io);
 DeleteIORequest((struct IORequest *)test_input_io);test_input_io=NULL;
 DeleteMsgPort(test_input_port);test_input_port=NULL;
}
/* A scripted second process for tests of blocking requesters: it waits until a
   window with the given title appears on the parent window's screen, then
   injects the events of the script through its own input.device handle, so the
   test task can sit in the requester. */
#include <dos/dostags.h>
struct ScriptEvent {uint32_t delay_ms,class_,code,qualifier;int32_t x,y;};
static struct ScriptEvent test_script[64];
static int test_script_length;
static volatile int test_script_state;
static char test_script_title[128];
static struct Screen *test_script_screen;
static struct Window *test_script_window;
void sdk_test_script_reset(void) {test_script_length=0;test_script_state=0;}
int sdk_test_script_add(uint32_t delay_ms,uint32_t class_,uint32_t code,uint32_t qualifier,int32_t x,int32_t y) {
 if(test_script_length>=64)return -1;
 test_script[test_script_length++]=(struct ScriptEvent){delay_ms,class_,code,qualifier,x,y};return 0;
}
static int script_window_visible(void) {
 for(struct Window *w=test_script_screen->FirstWindow;w;w=w->NextWindow)
  if(w->Title && !strcmp((const char *)w->Title,test_script_title)){test_script_window=w;return 1;}
 return 0;
}
/* A class with bit 8 set is a pointer event whose position is relative to the
   found window: non-negative values from its top left corner, negative values
   from its right and bottom edges. */
static void script_send(struct IOStdReq *io,const struct ScriptEvent *e) {
 struct InputEvent event;memset(&event,0,sizeof(event));
 int32_t x=e->x,y=e->y;
 if((e->class_&0x100) && test_script_window){
  struct Window *w=test_script_window;
  x=(x<0?w->LeftEdge+w->Width+x:w->LeftEdge+x);y=(y<0?w->TopEdge+w->Height+y:w->TopEdge+y);
 }
 event.ie_Class=(UBYTE)(e->class_&0xff);event.ie_Code=(UWORD)e->code;event.ie_Qualifier=(UWORD)e->qualifier;
 event.ie_X=(WORD)x;event.ie_Y=(WORD)y;
 io->io_Command=IND_ADDEVENT;io->io_Data=&event;io->io_Length=sizeof(event);
 DoIO((struct IORequest *)io);
}
static void script_entry(void) {
 int waited=0;
 while(!script_window_visible() && waited<500){Delay(1);++waited;}
 int found=script_window_visible();
 if(found)Delay(15);
 struct MsgPort *port=CreateMsgPort();
 struct IOStdReq *io=port?(struct IOStdReq *)CreateIORequest(port,sizeof(struct IOStdReq)):NULL;
 int opened=io && !OpenDevice((CONST_STRPTR)"input.device",0,(struct IORequest *)io,0);
 if(opened){
  if(found){
   for(int i=0;i<test_script_length;i++){
    if(test_script[i].delay_ms)Delay(test_script[i].delay_ms/20?test_script[i].delay_ms/20:1);
    script_send(io,&test_script[i]);
   }
  }else{
   /* the window never appeared: cancel whatever requester is open */
   struct ScriptEvent escape_down={0,1,0x45,0,0,0},escape_up={0,1,0xc5,0,0,0};
   script_send(io,&escape_down);script_send(io,&escape_up);
  }
  CloseDevice((struct IORequest *)io);
 }
 if(io)DeleteIORequest((struct IORequest *)io);
 if(port)DeleteMsgPort(port);
 test_script_state=found?2:3;
}
int sdk_test_script_start(const uint8_t *title,size_t length,void *parent_window) {
 if(length>=sizeof(test_script_title) || !parent_window || test_script_state==1)return -1;
 memcpy(test_script_title,title,length);test_script_title[length]=0;
 test_script_screen=((struct Window *)parent_window)->WScreen;
 test_script_state=1;
 struct TagItem tags[]={{NP_Entry,(IPTR)script_entry},{NP_Name,(IPTR)"ami-rust test script"},{NP_StackSize,65536},{TAG_DONE,0}};
 if(!CreateNewProc(tags)){test_script_state=0;return -2;}
 return 0;
}
/* Waits for the script to end: 2 it ran, 3 its window never appeared,
   1 still running at the timeout. */
int sdk_test_script_join(uint32_t timeout_ms) {
 uint32_t waited=0;
 while(test_script_state==1 && waited<timeout_ms){Delay(2);waited+=40;}
 int state=test_script_state;
 if(state!=1)Delay(15);
 return state;
}
/* Free memory as Exec reports it, to show that a program gave everything back. */
uint64_t sdk_test_avail_mem(void) {return (uint64_t)AvailMem(MEMF_ANY);}
static uint32_t fault_site,fault_nth,fault_seen,diagnostic_probe,secondary_on_diagnostic;
static APTR diagnostic_pool;
extern void ami_test_bind_diagnostics(volatile uint64_t *);
extern int ami_stack_calibrate(void);
extern void ami_test_phase(uint64_t);
extern void ami_test_measurement_expected(uint64_t);
void sdk_test_fault(uint32_t site,uint32_t nth) {fault_site=site;fault_nth=nth;fault_seen=0;}
void sdk_test_reset_fault(void) {fault_site=0;fault_seen=0;}
static int test_hit(uint32_t site) {return site==fault_site && ++fault_seen==fault_nth;}
/* Independent backend observer: records native acquisition/release effects,
   distinct from the product ownership registry and its statistics. */
struct BackendRecord { uintptr_t value;size_t bytes;unsigned kind,count; };
static struct BackendRecord backend[128];
static uint64_t backend_errors;
static ULONG initial_signal_mask;
static void backend_acquire(unsigned kind,uintptr_t value,size_t bytes) {
 for(size_t i=0;i<128;i++)if(backend[i].kind==kind&&backend[i].value==value){++backend[i].count;return;}
 for(size_t i=0;i<128;i++)if(!backend[i].count){backend[i]=(struct BackendRecord){value,bytes,kind,1};return;}
 ++backend_errors;
}
static int backend_release(unsigned kind,uintptr_t value,size_t bytes) {
 for(size_t i=0;i<128;i++)if(backend[i].count&&backend[i].kind==kind&&backend[i].value==value){
  if(kind==1&&backend[i].bytes!=bytes){++backend_errors;return 0;}
  if(!--backend[i].count)backend[i]=(struct BackendRecord){0};return 1;
 }
 ++backend_errors;return 0;
}
static uint64_t backend_live(void){uint64_t n=0;for(size_t i=0;i<128;i++)n+=backend[i].count;return n;}
static TEST_NOINLINE APTR test_allocmem(IPTR n,ULONG flags) {APTR p=test_hit(1)?NULL:AllocMem(n,flags);if(p)backend_acquire(1,(uintptr_t)p,n);return p;}
static TEST_NOINLINE void test_freemem(APTR p,IPTR n){if(backend_release(1,(uintptr_t)p,n))FreeMem(p,n);}
static TEST_NOINLINE BPTR test_open(CONST_STRPTR name,LONG mode) {if(test_hit(2)){SetIoErr((SIPTR)UINT64_C(0x123456789));return BNULL;}BPTR f=Open(name,mode);if(f)backend_acquire(2,(uintptr_t)f,0);return f;}
static TEST_NOINLINE LONG test_read(BPTR f,APTR p,LONG n) {if(test_hit(3)){SetIoErr((SIPTR)UINT64_C(0x123456789));return -1;}if(test_hit(10)&&n>1)n/=2;return Read(f,p,n);}
static TEST_NOINLINE LONG test_write(BPTR f,CONST_APTR p,LONG n) {if(test_hit(4)){SetIoErr((SIPTR)UINT64_C(0x123456789));return -1;}if(test_hit(12))return 0;if(test_hit(11)&&n>1)n/=2;return Write(f,p,n);}
static TEST_NOINLINE BOOL test_close(BPTR f) {if(!backend_release(2,(uintptr_t)f,0))return FALSE;BOOL result=Close(f);if(test_hit(5)){SetIoErr((SIPTR)UINT64_C(0x123456789));return FALSE;}return result;}
static TEST_NOINLINE struct Library *test_openlibrary(CONST_STRPTR name,ULONG version) {struct Library *l=test_hit(6)?NULL:OpenLibrary(name,version);if(l)backend_acquire(3,(uintptr_t)l,0);return l;}
static TEST_NOINLINE void test_closelibrary(struct Library *l){if(backend_release(3,(uintptr_t)l,0))CloseLibrary(l);}
static TEST_NOINLINE BYTE test_allocsignal(LONG bit) {BYTE b=test_hit(7)?-1:AllocSignal(bit);if(b>=0)backend_acquire(4,(uintptr_t)b,0);return b;}
static TEST_NOINLINE void test_freesignal(LONG bit){if(backend_release(4,(uintptr_t)bit,0))FreeSignal(bit);}
static TEST_NOINLINE struct MsgPort *test_createmsgport(void) {struct MsgPort *p=test_hit(8)?NULL:CreateMsgPort();if(p)backend_acquire(5,(uintptr_t)p,0);return p;}
static TEST_NOINLINE void test_deletemsgport(struct MsgPort *p){if(backend_release(5,(uintptr_t)p,0))DeleteMsgPort(p);}
static TEST_NOINLINE BYTE test_opendevice(CONST_STRPTR name,IPTR unit,struct IORequest *io,ULONG flags) {BYTE r=test_hit(16)?(BYTE)-1:OpenDevice(name,unit,io,flags);if(!r)backend_acquire(6,(uintptr_t)io,0);return r;}
static TEST_NOINLINE void test_closedevice(struct IORequest *io){if(backend_release(6,(uintptr_t)io,0))CloseDevice(io);}
static TEST_NOINLINE BPTR test_lock(CONST_STRPTR name,LONG mode){BPTR l=test_hit(17)?BNULL:Lock(name,mode);if(l)backend_acquire(7,(uintptr_t)l,0);return l;}
static TEST_NOINLINE BPTR test_createdir(CONST_STRPTR name){BPTR l=CreateDir(name);if(l)backend_acquire(7,(uintptr_t)l,0);return l;}
static TEST_NOINLINE BOOL test_unlock(BPTR l){if(!backend_release(7,(uintptr_t)l,0))return FALSE;return UnLock(l);}
static TEST_NOINLINE APTR test_allocdosobject(ULONG type,struct TagItem *tags){APTR o=test_hit(18)?NULL:AllocDosObject(type,tags);if(o)backend_acquire(8,(uintptr_t)o,0);return o;}
static TEST_NOINLINE void test_freedosobject(ULONG type,APTR o){if(backend_release(8,(uintptr_t)o,0))FreeDosObject(type,o);}
#ifndef AMI_RUST_ABI11
static TEST_NOINLINE APTR test_allocdosobject64(ULONG type,const struct TagItem *tags){APTR o=test_hit(18)?NULL:AllocDosObject64(type,tags);if(o)backend_acquire(8,(uintptr_t)o,0);return o;}
static TEST_NOINLINE void test_freedosobject64(ULONG type,APTR o){if(backend_release(8,(uintptr_t)o,0))FreeDosObject64(type,o);}
#endif
#undef FreeMem
#undef CloseLibrary
#undef FreeSignal
#undef DeleteMsgPort
#undef AllocMem
#undef Open
#undef Read
#undef Write
#undef Close
#undef OpenLibrary
#undef AllocSignal
#undef CreateMsgPort
#undef OpenDevice
#undef CloseDevice
#undef Lock
#undef CreateDir
#undef UnLock
#undef AllocDosObject
#undef FreeDosObject
#ifndef AMI_RUST_ABI11
#undef AllocDosObject64
#undef FreeDosObject64
#endif
#define FreeMem test_freemem
#define CloseLibrary test_closelibrary
#define FreeSignal test_freesignal
#define DeleteMsgPort test_deletemsgport
#define AllocMem test_allocmem
#define Open test_open
#define Read test_read
#define Write test_write
#define Close test_close
#define OpenLibrary test_openlibrary
#define AllocSignal test_allocsignal
#define CreateMsgPort test_createmsgport
#define OpenDevice test_opendevice
#define CloseDevice test_closedevice
#define Lock test_lock
#define CreateDir test_createdir
#define UnLock test_unlock
#define AllocDosObject test_allocdosobject
#define FreeDosObject test_freedosobject
#ifndef AMI_RUST_ABI11
#define AllocDosObject64 test_allocdosobject64
#define FreeDosObject64 test_freedosobject64
#endif
#else
#define test_hit(site) 0
#endif
