#include "../../native/sdk.h"
#include <stdio.h>

#define CHECK(expression) do { \
 if(!(expression)){ \
  fprintf(stderr,"allocation layout fixture failed at line %d: %s\n",__LINE__,#expression); \
  return 1; \
 } \
} while(0)

struct TestBlock { uintptr_t next,previous,user; size_t size,alignment,total,charge; };

int main(void) {
 AmiSdkAllocationLayout layout;
 CHECK(ami_sdk_allocation_layout(0,1,sizeof(struct TestBlock),&layout));
 CHECK(layout.payload==1 && layout.alignment==AMI_SDK_MIN_ALLOCATION_ALIGNMENT);
 CHECK(ami_sdk_allocation_layout(32,2,sizeof(struct TestBlock),&layout));
 CHECK(layout.alignment==AMI_SDK_MIN_ALLOCATION_ALIGNMENT);
 CHECK(ami_sdk_allocation_layout(32,4096,sizeof(struct TestBlock),&layout));
 CHECK(layout.alignment==AMI_SDK_MAX_ALLOCATION_ALIGNMENT);
 CHECK(!ami_sdk_allocation_layout(32,0,sizeof(struct TestBlock),&layout));
 CHECK(!ami_sdk_allocation_layout(32,3,sizeof(struct TestBlock),&layout));
 CHECK(!ami_sdk_allocation_layout(32,8192,sizeof(struct TestBlock),&layout));

 CHECK(ami_sdk_allocation_layout(2*1024*1024,8,sizeof(struct TestBlock),&layout));
 size_t combined_charge=0;
 for(size_t i=0;i<3;i++){
  CHECK(ami_sdk_allocation_layout(4*1024*1024,8,sizeof(struct TestBlock),&layout));
  CHECK(ami_sdk_allocation_add_charge(combined_charge,layout.charge,&combined_charge));
 }
 CHECK(combined_charge>16*1024*1024);

 CHECK(ami_sdk_allocation_layout(64,4096,sizeof(struct TestBlock),&layout));
 uintptr_t user=0;
 uintptr_t base=(uintptr_t)0x1000;
 CHECK(ami_sdk_allocation_user_address(base,&layout,&user));
 CHECK(user%layout.alignment==0 && user>=base+layout.header_size);
 CHECK(user-base<=layout.total && layout.payload<=layout.total-(user-base));
 uintptr_t near_end=UINTPTR_MAX-(uintptr_t)layout.total+(uintptr_t)1;
 CHECK(!ami_sdk_allocation_user_address(near_end,&layout,&user));

 size_t next=0;
 size_t exact_current=SIZE_MAX-layout.charge;
 CHECK(ami_sdk_allocation_add_charge(exact_current,layout.charge,&next));
 CHECK(next==SIZE_MAX);
 CHECK(!ami_sdk_allocation_add_charge(exact_current+1,layout.charge,&next));
 CHECK(!ami_sdk_allocation_layout(SIZE_MAX,8,sizeof(struct TestBlock),&layout));
 CHECK(!ami_sdk_allocation_layout((size_t)PTRDIFF_MAX,8,sizeof(struct TestBlock),&layout));

 size_t low=0,high=(size_t)PTRDIFF_MAX;
 CHECK(ami_sdk_allocation_layout(low,8,sizeof(struct TestBlock),&layout));
 while(low<high){
  size_t distance=high-low;
  size_t middle=low+distance/2+distance%2;
  if(ami_sdk_allocation_layout(middle,8,sizeof(struct TestBlock),&layout))low=middle;
  else high=middle-1;
 }
 CHECK(ami_sdk_allocation_layout(low,8,sizeof(struct TestBlock),&layout));
 CHECK(low<SIZE_MAX);
 CHECK(!ami_sdk_allocation_layout(low+1,8,sizeof(struct TestBlock),&layout));
 return 0;
}
