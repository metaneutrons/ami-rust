/* Qualification-only probes for ABI calls with 7 to 12 arguments. They return a
   hash of the library base and every argument so a generated call can be
   checked position by position. ABI-v1 passes the base as the last argument;
   ABI-v11 passes it in r12, which a one-instruction thunk records before it
   jumps to the C body. */
#ifndef AMI_RUST_TEST_PROBE_H
#define AMI_RUST_TEST_PROBE_H
#ifdef AMI_SDK_TESTING
#include <stdint.h>
#ifndef AMI_RUST_ABI11
static uint64_t probe_abi1_7(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;return h;}
static uint64_t probe_abi1_8(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;return h;}
static uint64_t probe_abi1_9(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;return h;}
static uint64_t probe_abi1_10(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;return h;}
static uint64_t probe_abi1_11(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10,uint16_t a11,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;h=h*31+(uint64_t)a11;return h;}
static uint64_t probe_abi1_12(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10,uint16_t a11,uint8_t a12,const void *base){uint64_t h=(uint64_t)(uintptr_t)base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;h=h*31+(uint64_t)a11;h=h*31+(uint64_t)a12;return h;}
static const void *probe_function(unsigned n){
 switch(n){
  case 7: return (const void *)probe_abi1_7;
  case 8: return (const void *)probe_abi1_8;
  case 9: return (const void *)probe_abi1_9;
  case 10: return (const void *)probe_abi1_10;
  case 11: return (const void *)probe_abi1_11;
  case 12: return (const void *)probe_abi1_12;
 default: return 0;
 }
}
#else
volatile uintptr_t sdk_test_probe_base,sdk_test_probe_sp;
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_7(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;return h;}
__asm__(".text\n.type probe_thunk_7,@function\nprobe_thunk_7:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_7\n");
extern void probe_thunk_7(void);
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_8(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;return h;}
__asm__(".text\n.type probe_thunk_8,@function\nprobe_thunk_8:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_8\n");
extern void probe_thunk_8(void);
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_9(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;return h;}
__asm__(".text\n.type probe_thunk_9,@function\nprobe_thunk_9:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_9\n");
extern void probe_thunk_9(void);
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_10(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;return h;}
__asm__(".text\n.type probe_thunk_10,@function\nprobe_thunk_10:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_10\n");
extern void probe_thunk_10(void);
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_11(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10,uint16_t a11){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;h=h*31+(uint64_t)a11;return h;}
__asm__(".text\n.type probe_thunk_11,@function\nprobe_thunk_11:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_11\n");
extern void probe_thunk_11(void);
__attribute__((used,noinline)) uint64_t sdk_test_probe_abi11_12(uint64_t a1,uint32_t a2,const void * a3,int32_t a4,uint16_t a5,uint8_t a6,uint64_t a7,uint32_t a8,const void * a9,int32_t a10,uint16_t a11,uint8_t a12){uint64_t h=(uint64_t)sdk_test_probe_base;h=h*31+a1;h=h*31+(uint64_t)a2;h=h*31+(uint64_t)(uintptr_t)a3;h=h*31+(uint64_t)(uint32_t)a4;h=h*31+(uint64_t)a5;h=h*31+(uint64_t)a6;h=h*31+a7;h=h*31+(uint64_t)a8;h=h*31+(uint64_t)(uintptr_t)a9;h=h*31+(uint64_t)(uint32_t)a10;h=h*31+(uint64_t)a11;h=h*31+(uint64_t)a12;return h;}
__asm__(".text\n.type probe_thunk_12,@function\nprobe_thunk_12:\n movq %r12,sdk_test_probe_base(%rip)\n movq %rsp,sdk_test_probe_sp(%rip)\n jmp sdk_test_probe_abi11_12\n");
extern void probe_thunk_12(void);
static const void *probe_function(unsigned n){
 switch(n){
  case 7: return (const void *)probe_thunk_7;
  case 8: return (const void *)probe_thunk_8;
  case 9: return (const void *)probe_thunk_9;
  case 10: return (const void *)probe_thunk_10;
  case 11: return (const void *)probe_thunk_11;
  case 12: return (const void *)probe_thunk_12;
 default: return 0;
 }
}
#endif
const void *sdk_test_probe_function(unsigned n){return probe_function(n);}
/* Stack pointer at the callee's entry (return address pushed); ABI-v1 callees are
   compiled C, so 8 stands for the aligned case there. */
#ifdef AMI_RUST_ABI11
uintptr_t sdk_test_probe_entry_sp(void){return sdk_test_probe_sp;}
#else
uintptr_t sdk_test_probe_entry_sp(void){return 8;}
#endif
#endif
#endif
