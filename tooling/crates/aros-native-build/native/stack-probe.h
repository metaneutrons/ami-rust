/* Qualification-only stack paint/canary instrument, derived from M0 r29 entry.
   Public task stack bounds only; no allocator or OS call during paint/damage. */
#ifdef AMI_SDK_TESTING
#define STACK_BYTES 131072UL
#define STACK_LIMIT 98304UL
static uintptr_t paint_lower,paint_upper,paint_end;
static uint64_t canary_counter;
size_t ami_stack_used(void) {
 if(!paint_lower || paint_upper-paint_lower!=STACK_BYTES)return STACK_BYTES;
 uintptr_t first=paint_end;
 for(uintptr_t p=paint_lower+64;p<paint_end;p++)if(*(volatile uint8_t *)p!=0xa5){first=p;break;}
 return paint_upper-first;
}
int ami_stack_canary(void) {
 for(size_t i=0;i<64;i++)if(*(volatile uint8_t *)(paint_lower+i)!=(uint8_t)(0xc3^i)){++canary_counter;return 0;}
 return paint_lower!=0;
}
static int ami_stack_prepare(struct Task *t) {
 uintptr_t sp;__asm__ volatile("movq %%rsp,%0":"=r"(sp)::"memory");
 paint_lower=(uintptr_t)t->tc_SPLower;paint_upper=(uintptr_t)t->tc_SPUpper;
 if(!paint_lower || paint_upper-paint_lower!=STACK_BYTES || sp<=paint_lower+576 || sp>=paint_upper)return 20;
 paint_end=sp-512;
 for(uintptr_t p=paint_lower;p<paint_end;p++)*(volatile uint8_t *)p=0xa5;
 for(size_t i=0;i<64;i++)*(volatile uint8_t *)(paint_lower+i)=(uint8_t)(0xc3^i);
 uint8_t saved=*(volatile uint8_t *)paint_lower;*(volatile uint8_t *)paint_lower=saved^1;
 int detected=!ami_stack_canary();*(volatile uint8_t *)paint_lower=saved;
 return detected && ami_stack_canary()?0:20;
}
static void __attribute__((noinline)) stack_fixture(void) {
 volatile uint8_t bytes[32768];for(size_t i=0;i<sizeof(bytes);i++)bytes[i]=0x5a;
 __asm__ volatile(""::"r"(&bytes[0]):"memory");
}
int ami_stack_calibrate(void) {
 size_t before=ami_stack_used();stack_fixture();size_t after=ami_stack_used();
 volatile uint8_t *p=(void *)(paint_upper-STACK_LIMIT-4096);
 uint8_t old=*p;*p=old^1;size_t excess=ami_stack_used();*p=old;
 if(after<32768 || after<before || excess<=STACK_LIMIT || !ami_stack_canary())return 20;
 sdk_diagnostic((const uint8_t *)"[m1-stack] calibrated",21,after);
 sdk_diagnostic((const uint8_t *)"[m1-stack] excess-rejected",26,excess);
 return 0;
}
static int ami_stack_finish(void) {
 sdk_diagnostic((const uint8_t *)"[m1-stack] reserved",19,STACK_BYTES);
 sdk_diagnostic((const uint8_t *)"[m1-stack] canary",17,ami_stack_canary());
 sdk_diagnostic((const uint8_t *)"[m1-stack] canary-counter",25,canary_counter);
 sdk_diagnostic((const uint8_t *)"[m1-stack] used",15,ami_stack_used());
 return ami_stack_canary() && ami_stack_used()<=STACK_LIMIT?0:20;
}
#endif
