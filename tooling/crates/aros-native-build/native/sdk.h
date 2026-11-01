/* Native x86-64 AROS ABI-v1 bridge. External AROS SDK contracts retain upstream rights. */
#ifndef AMI_RUST_SDK_H
#define AMI_RUST_SDK_H
#include <stdint.h>
#include <stddef.h>
typedef struct { int32_t kind; int64_t native; } SdkError;
typedef struct { size_t blocks, backing_charge, peak_charge, files, libraries, ports, signals, messages, refusals, devices, requests, directories; } SdkStats;
/* One directory entry; the layout is checked against the Rust declaration. */
typedef struct { uint64_t size;uint32_t protection,name_length;int32_t entry_type,directory_type,days,minutes,ticks;uint32_t size_exact;uint8_t name[108]; } SdkEntry;

/* Shared checked layout arithmetic for the native allocator and host tests. */
#define AMI_SDK_MIN_ALLOCATION_ALIGNMENT ((size_t)8)
#define AMI_SDK_MAX_ALLOCATION_ALIGNMENT ((size_t)4096)
typedef struct {
 size_t payload, alignment, header_size, total, charge;
} AmiSdkAllocationLayout;

static inline int ami_sdk_allocation_alignment_valid(size_t alignment) {
 return alignment && !(alignment & (alignment - 1)) &&
        alignment <= AMI_SDK_MAX_ALLOCATION_ALIGNMENT;
}

static inline int ami_sdk_allocation_layout(size_t size,size_t alignment,
                                             size_t header_size,
                                             AmiSdkAllocationLayout *layout) {
 if(!layout || !ami_sdk_allocation_alignment_valid(alignment))return 0;
 size_t effective=alignment<AMI_SDK_MIN_ALLOCATION_ALIGNMENT?
                   AMI_SDK_MIN_ALLOCATION_ALIGNMENT:alignment;
 size_t payload=size?size:1;
#ifdef PTRDIFF_MAX
 size_t max_total=(size_t)PTRDIFF_MAX;
#else
 /* Older AROS SDK headers expose size_t but not the C99 PTRDIFF_MAX macro. */
 size_t max_total=SIZE_MAX>>1;
#endif
 size_t alignment_padding=effective-1;
 if(header_size>max_total || alignment_padding>max_total-header_size)return 0;
 size_t overhead=header_size+alignment_padding;
 if(payload>max_total-overhead)return 0;
 size_t total=overhead+payload;
 if(total>(SIZE_MAX-(size_t)128)/(size_t)2)return 0;
 layout->payload=payload;
 layout->alignment=effective;
 layout->header_size=header_size;
 layout->total=total;
 layout->charge=(size_t)2*total+(size_t)128;
 return 1;
}

static inline int ami_sdk_allocation_add_charge(size_t current,size_t charge,
                                                 size_t *next) {
 if(!next || charge>SIZE_MAX-current)return 0;
 *next=current+charge;
 return 1;
}

static inline int ami_sdk_allocation_user_address(uintptr_t base,
                                                   const AmiSdkAllocationLayout *layout,
                                                   uintptr_t *user_address) {
 if(!layout || !user_address || layout->alignment<AMI_SDK_MIN_ALLOCATION_ALIGNMENT ||
    !ami_sdk_allocation_alignment_valid(layout->alignment))return 0;
 uintptr_t total=(uintptr_t)layout->total;
 uintptr_t header=(uintptr_t)layout->header_size;
 uintptr_t payload=(uintptr_t)layout->payload;
 if((size_t)total!=layout->total || (size_t)header!=layout->header_size ||
    (size_t)payload!=layout->payload || header>total ||
    total>UINTPTR_MAX-base)return 0;
 uintptr_t start=base+header;
 uintptr_t mask=(uintptr_t)(layout->alignment-1);
 uintptr_t padding=((uintptr_t)0-start)&mask;
 if(padding>UINTPTR_MAX-start)return 0;
 uintptr_t aligned=start+padding;
 if(aligned<base)return 0;
 uintptr_t offset=aligned-base;
 if(offset>total || payload>total-offset)return 0;
 *user_address=aligned;
 return 1;
}

int sdk_begin(int argc, char **argv);
int sdk_end(void);
uint64_t sdk_context(void);
uint64_t sdk_claim_context(void);
uintptr_t sdk_do_method_a(void *,void *);
uintptr_t sdk_do_super_method_a(void *,void *,void *);
uintptr_t sdk_coerce_method_a(void *,void *,void *);
size_t sdk_arg_count(uint64_t);
const uint8_t *sdk_arg(uint64_t,size_t,size_t *);
void *sdk_alloc(size_t,size_t);
void sdk_dealloc(void *,size_t,size_t);
void sdk_diagnostic(const uint8_t *,size_t,uint64_t);
_Noreturn void sdk_fatal(uint64_t);
SdkStats sdk_stats(void);
uint64_t sdk_library_open(uint64_t,const uint8_t *,uint16_t,SdkError *);
void *sdk_library_base(uint64_t,uint64_t);
int sdk_library_close(uint64_t,uint64_t,SdkError *);
uint64_t sdk_file_open(uint64_t,const uint8_t *,int32_t,SdkError *);
int sdk_file_close(uint64_t,uint64_t,SdkError *);
int64_t sdk_file_io(uint64_t,uint64_t,uint8_t *,size_t,int32_t,SdkError *);
uint64_t sdk_stdout(uint64_t);
uint64_t sdk_stderr(uint64_t);
uint64_t sdk_signal_new(uint64_t,SdkError *);
int sdk_signal_drop(uint64_t,uint64_t,SdkError *);
int sdk_signal_post(uint64_t,uint64_t,SdkError *);
int sdk_signal_wait(uint64_t,uint64_t,SdkError *);
int sdk_signal_wait_mask(uint64_t,uint32_t,uint32_t *,SdkError *);
uint64_t sdk_port_new(uint64_t,SdkError *);
int sdk_port_drop(uint64_t,uint64_t,SdkError *);
uint64_t sdk_message_new(uint64_t,const uint8_t *,size_t,SdkError *);
int sdk_message_drop(uint64_t,uint64_t,SdkError *);
int sdk_message_copy(uint64_t,uint64_t,uint8_t *,size_t,SdkError *);
int sdk_port_put(uint64_t,uint64_t,uint64_t,uint64_t,SdkError *);
int sdk_port_receive(uint64_t,uint64_t,uint64_t,SdkError *);
int sdk_message_reply(uint64_t,uint64_t,SdkError *);
uint64_t sdk_device_open(uint64_t,const uint8_t *,uint32_t,uint32_t,SdkError *);
int sdk_device_close(uint64_t,uint64_t,SdkError *);
uint32_t sdk_device_signal_mask(uint64_t,uint64_t);
void *sdk_device_base(uint64_t,uint64_t);
size_t sdk_timer_layout(uint64_t *,size_t);
uint64_t sdk_io_new(uint64_t,uint64_t,int32_t,size_t,SdkError *);
int sdk_io_drop(uint64_t,uint64_t,SdkError *);
int sdk_io_prepare(uint64_t,uint64_t,uint32_t,uint32_t,size_t,uint32_t,SdkError *);
int sdk_io_write(uint64_t,uint64_t,const uint8_t *,size_t,SdkError *);
int64_t sdk_io_read(uint64_t,uint64_t,uint8_t *,size_t,SdkError *);
int sdk_io_set_time(uint64_t,uint64_t,uint32_t,uint32_t,SdkError *);
int sdk_io_time(uint64_t,uint64_t,uint32_t *,uint32_t *,SdkError *);
int sdk_io_result(uint64_t,uint64_t,int32_t *,uint32_t *,SdkError *);
int sdk_io_do(uint64_t,uint64_t,int32_t *,SdkError *);
int sdk_io_send(uint64_t,uint64_t,SdkError *);
int sdk_io_check(uint64_t,uint64_t,SdkError *);
int sdk_io_wait(uint64_t,uint64_t,int32_t *,SdkError *);
int sdk_io_abort(uint64_t,uint64_t,SdkError *);
uint64_t sdk_dir_open(uint64_t,const uint8_t *,SdkError *);
int sdk_dir_next(uint64_t,uint64_t,SdkEntry *,SdkError *);
int sdk_dir_close(uint64_t,uint64_t,SdkError *);
int sdk_entry_info(uint64_t,const uint8_t *,SdkEntry *,SdkError *);
int sdk_make_dir(uint64_t,const uint8_t *,SdkError *);
int sdk_delete(uint64_t,const uint8_t *,SdkError *);
int sdk_rename(uint64_t,const uint8_t *,const uint8_t *,SdkError *);
int64_t sdk_cwd_get(uint64_t,uint8_t *,size_t,SdkError *);
int sdk_cwd_set(uint64_t,const uint8_t *,SdkError *);
int64_t sdk_var_get(uint64_t,const uint8_t *,uint8_t *,size_t,int32_t,SdkError *);
int sdk_var_set(uint64_t,const uint8_t *,const uint8_t *,size_t,int32_t,SdkError *);
int sdk_var_delete(uint64_t,const uint8_t *,int32_t,SdkError *);
int sdk_file_seek(uint64_t,uint64_t,int32_t,int64_t,uint64_t *,SdkError *);
int sdk_file_position(uint64_t,uint64_t,uint64_t *,SdkError *);
int sdk_file_size(uint64_t,uint64_t,uint64_t *,SdkError *);
int sdk_callback(uint64_t,uint64_t (*)(void *,uint64_t),void *,uint64_t,uint64_t *,SdkError *);
/* Independent C oracle: count then values; no raw Rust structs enter OS calls. */
size_t sdk_layout(uint64_t *,size_t);
uint64_t sdk_scalar(int32_t,uint32_t,uintptr_t,uint64_t,size_t);
#endif
