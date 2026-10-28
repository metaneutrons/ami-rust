#include <stddef.h>
#include <proto/dos.h>
#include <proto/exec.h>
int main(int argc,char **argv) {
 if(argc!=2)return 10;
 BPTR file=Open((CONST_STRPTR)argv[1],MODE_OLDFILE);if(!file)return 10;
 UBYTE buffer[256];LONG n;size_t total=0;
 const char *start="[m1-status] begin\n";while(*start)RawPutChar(*start++);
 while((n=Read(file,buffer,sizeof(buffer)))>0){total+=(size_t)n;if(total>4096){Close(file);return 20;}for(LONG i=0;i<n;i++)RawPutChar(buffer[i]);}
 BOOL ok=Close(file);if(n<0||!ok)return 10;
 const char *end="[m1-status] end\n";while(*end)RawPutChar(*end++);return 0;
}
