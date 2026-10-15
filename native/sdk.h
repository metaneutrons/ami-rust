/* Native x86-64 AROS ABI-v1 bridge. External AROS SDK contracts retain upstream rights. */
#ifndef AMI_RUST_SDK_H
#define AMI_RUST_SDK_H
#include <stdint.h>
#include <stddef.h>
typedef struct { int32_t kind; int64_t native; } SdkError;
typedef struct { size_t blocks, backing_charge, peak_charge, files, libraries, ports, signals, messages, refusals; } SdkStats;
int sdk_begin(int argc, char **argv);
int sdk_end(void);
uint64_t sdk_context(void);
uint64_t sdk_claim_context(void);
size_t sdk_arg_count(uint64_t);
const uint8_t *sdk_arg(uint64_t,size_t,size_t *);
void *sdk_alloc(size_t,size_t);
void sdk_dealloc(void *,size_t,size_t);
void sdk_diagnostic(const uint8_t *,size_t,uint64_t);
_Noreturn void sdk_fatal(uint64_t);
SdkStats sdk_stats(void);
uint64_t sdk_library_open(uint64_t,const uint8_t *,uint16_t,SdkError *);
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
uint64_t sdk_port_new(uint64_t,SdkError *);
int sdk_port_drop(uint64_t,uint64_t,SdkError *);
uint64_t sdk_message_new(uint64_t,const uint8_t *,size_t,SdkError *);
int sdk_message_drop(uint64_t,uint64_t,SdkError *);
int sdk_message_copy(uint64_t,uint64_t,uint8_t *,size_t,SdkError *);
int sdk_port_put(uint64_t,uint64_t,uint64_t,uint64_t,SdkError *);
int sdk_port_receive(uint64_t,uint64_t,uint64_t,SdkError *);
int sdk_message_reply(uint64_t,uint64_t,SdkError *);
int sdk_callback(uint64_t,uint64_t (*)(void *,uint64_t),void *,uint64_t,uint64_t *,SdkError *);
/* Independent C oracle: count then values; no raw Rust structs enter OS calls. */
size_t sdk_layout(uint64_t *,size_t);
uint64_t sdk_scalar(int32_t,uint32_t,uintptr_t,uint64_t,size_t);
#endif
