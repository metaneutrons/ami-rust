/* Disposable native R1 stderr probe. No shell stderr-redirection assumption. */
#include <exec/tasks.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <clib/debug_protos.h>
#include <aros/debug.h>
#include <string.h>

static const char input_path[]="RAM:ami-rust-m1/one byte";
static const char output_path[]="RAM:ami-rust-m1/stdout.txt";
static const char error_path[]="RAM:ami-rust-m1/stderr.txt";

static int dump(const char *path,const char *name) {
 BPTR f=Open((CONST_STRPTR)path,MODE_OLDFILE);if(!f)return 0;
 UBYTE bytes[256];LONG n;unsigned total=0;
 bug("[r1-stream] begin %s encoding=hex\n",name);
 while((n=Read(f,bytes,sizeof(bytes)))>0){
  if(total+(unsigned)n>4096){Close(f);return 0;}
  total+=(unsigned)n;
  /* The serial backend expands newlines. Encode actual file bytes before
     transport so the host checks them without newline normalization. */
  static const char hex[]="0123456789abcdef";
  for(LONG i=0;i<n;i++){RawPutChar(hex[bytes[i]>>4]);RawPutChar(hex[bytes[i]&15]);}
 }
 BOOL closed=Close(f);if(n<0 || !closed)return 0;
 RawPutChar('\n');bug("[r1-stream] end %s bytes=%lu\n",name,(unsigned long)total);return 1;
}

static int run_case(const char *id,const char *program,const char *arguments,int expected,int fallback) {
 struct Task *task=FindTask(NULL);if(!task || task->tc_Node.ln_Type!=NT_PROCESS)return 0;
 struct Process *process=(struct Process *)task;
 BPTR out=Open((CONST_STRPTR)output_path,MODE_NEWFILE);if(!out)return 0;
 BPTR err=Open((CONST_STRPTR)error_path,MODE_NEWFILE);if(!err){Close(out);return 0;}
 BPTR saved_out=process->pr_COS,saved_err=process->pr_CES;
 process->pr_COS=out;process->pr_CES=fallback?BNULL:err;
 BPTR seg=LoadSeg((CONST_STRPTR)program);LONG rc=20;
 if(seg){rc=RunCommand(seg,131072,(STRPTR)arguments,(ULONG)strlen(arguments));UnLoadSeg(seg);}
 process->pr_COS=saved_out;process->pr_CES=saved_err;
 BOOL close_out=Close(out),close_err=Close(err);
 bug("[r1-probe] begin %s rc=%ld expected=%ld\n",id,(long)rc,(long)expected);
 int captured=dump(output_path,"stdout") && dump(error_path,"stderr");
 bug("[r1-probe] end %s streams_closed=%ld captured=%ld\n",id,(long)(close_out && close_err),(long)captured);
 return seg && rc==expected && close_out && close_err && captured;
}

int main(int argc,char **argv) {
 if(argc!=3)return 20;
 BPTR lock=CreateDir((CONST_STRPTR)"RAM:ami-rust-m1");
 if(lock)UnLock(lock);
 else{lock=Lock((CONST_STRPTR)"RAM:ami-rust-m1",ACCESS_READ);if(!lock)return 20;UnLock(lock);}
 BPTR one=Open((CONST_STRPTR)input_path,MODE_NEWFILE);if(!one)return 20;
 LONG written=Write(one,"a",1);BOOL closed=Close(one);if(written!=1 || !closed)return 20;
 int ok=run_case("fixture",argv[1],"stderr\n",0,0);
 ok=run_case("usage",argv[2],"\n",10,0) && ok;
 ok=run_case("mixed",argv[2],"\"RAM:ami-rust-m1/absent file\" \"RAM:ami-rust-m1/one byte\"\n",10,0) && ok;
 ok=run_case("fallback",argv[2],"\"RAM:ami-rust-m1/absent file\"\n",10,1) && ok;
 one=Open((CONST_STRPTR)input_path,MODE_OLDFILE);if(!one)return 20;
 UBYTE data[2];LONG read=Read(one,data,sizeof(data));closed=Close(one);
 int unchanged=read==1 && data[0]=='a' && closed;
 bug("[r1-probe] input_unchanged=%ld result=%ld\n",(long)unchanged,(long)(ok && unchanged));
 return ok && unchanged?0:20;
}
