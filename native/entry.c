/* Pre-parser gate. Keep the leading startup trampoline free of data access;
   native preflight lives in regular .text, before immutable SDK startup. */
#include <exec/execbase.h>
#include <exec/tasks.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <aros/asmcall.h>
#include <aros/startup.h>
#include "sdk.h"
#include "compatibility-gates.h"
#include "stack-probe.h"
extern SIPTR ami_sdk_startup_entry(STRPTR,ULONG,struct ExecBase *);
static SIPTR __attribute__((noinline)) entry_body(STRPTR argstr,ULONG argsize,struct ExecBase *sysBase) {
 if(!sysBase || !sysBase->ThisTask || (IPTR)sysBase->ThisTask->tc_SPUpper-(IPTR)sysBase->ThisTask->tc_SPLower!=131072)return 20;
 if(!compatible_exec(&sysBase->LibNode))return 20;
#ifdef AMI_SDK_TESTING
 SysBase=sysBase;
 if(ami_stack_prepare(sysBase->ThisTask))return 20;
#endif
 if(argsize>4096 || (argsize && !argstr))return 10;
 /* Stock startup/stdio use DOS before sdk_begin. Open at zero minimum, inspect
    the header, then close this preflight ref on both success and refusal. */
 SysBase=sysBase;
 struct Library *dos=OpenLibrary((CONST_STRPTR)"dos.library",0);
 if(!dos)return 20;
 int compatible=compatible_dos(dos);
 CloseLibrary(dos);
 if(!compatible)return 20;
 SIPTR result=ami_sdk_startup_entry(argstr,argsize,sysBase);
#ifdef AMI_SDK_TESTING
 if(ami_stack_finish())return 20;
#endif
 return result;
}
__startup AROS_PROCH(__startup_entry,argstr,argsize,sysBase) {
 AROS_PROCFUNC_INIT
 return entry_body(argstr,argsize,sysBase);
 AROS_PROCFUNC_EXIT
}
