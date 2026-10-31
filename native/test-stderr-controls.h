/* Native R1 stderr controls; only included by AMI_SDK_TESTING sdk.c.
   No process-owned stream is closed here. Restore before file cleanup. */
static BPTR stderr_saved_error,stderr_saved_output;
static int stderr_route_active;
static void test_stderr_restore(void) {
 if(stderr_route_active && owner && owner->tc_Node.ln_Type==NT_PROCESS){
  struct Process *p=(struct Process *)owner;
  p->pr_CES=stderr_saved_error;p->pr_COS=stderr_saved_output;
 }
 stderr_route_active=0;
}
int sdk_test_stderr_redirect(uint64_t key,uint64_t file_token,uint32_t route) {
 if(own(key,NULL) || owner->tc_Node.ln_Type!=NT_PROCESS || route>3)return -1;
 if(!route){test_stderr_restore();return 0;}
 if(stderr_route_active)return -1;
 BPTR file=BNULL;
 if(route!=3){
  struct FileSlot *slot=(struct FileSlot *)record_find(&files,file_token,KIND_FILE);
  if(!slot || !slot->handle)return -1;
  file=slot->handle;
 }
 struct Process *p=(struct Process *)owner;
 stderr_saved_error=p->pr_CES;stderr_saved_output=p->pr_COS;stderr_route_active=1;
 if(route==1)p->pr_CES=file;
 else{p->pr_CES=BNULL;p->pr_COS=file;}
 return 0;
}
int sdk_test_stderr_not_process(uint64_t key) {
 if(own(key,NULL) || owner->tc_Node.ln_Type!=NT_PROCESS)return -1;
 UBYTE original_type=owner->tc_Node.ln_Type;
 owner->tc_Node.ln_Type=NT_TASK;
 uint64_t token=sdk_stderr(key);uint8_t byte=0;SdkError error;
 int64_t result=sdk_file_io(key,ERROR_OUTPUT_TOKEN,&byte,1,1,&error);
 owner->tc_Node.ln_Type=original_type;
 return !token && result==-1 && error.kind==5?0:-1;
}
