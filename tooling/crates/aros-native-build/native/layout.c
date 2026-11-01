/* Independent native-header layout oracle, not a Rust-derived expected table. */
#include "sdk.h"
#include <exec/ports.h>
#include <exec/libraries.h>
#include <dos/dosextens.h>
#include <devices/timer.h>
#if (__DOS64)
#error "M1 preserves the qualified legacy FileInfoBlock32 profile"
#endif
_Static_assert(sizeof(LONG)==4,"AROS LONG32");
_Static_assert(sizeof(IPTR)==8,"AROS pointer64");
_Static_assert(sizeof(((struct FileInfoBlock*)0)->fib_Size)==4,"qualified FIB32");
#define LAYOUT(T,...) sizeof(T),_Alignof(T),__VA_ARGS__
#define OFF(T,F) offsetof(T,F)
static const size_t c_layout[]={
 LAYOUT(struct Node,OFF(struct Node,ln_Succ),OFF(struct Node,ln_Pred),OFF(struct Node,ln_Type),OFF(struct Node,ln_Pri),OFF(struct Node,ln_Name)),
#ifdef AMI_RUST_ABI11
 LAYOUT(struct Library,OFF(struct Library,lib_Node),OFF(struct Library,lib_Flags),OFF(struct Library,lib_pad),OFF(struct Library,lib_NegSize),OFF(struct Library,lib_PosSize),OFF(struct Library,lib_Version),OFF(struct Library,lib_Revision),OFF(struct Library,lib_IdString),OFF(struct Library,lib_Sum),OFF(struct Library,lib_OpenCnt)),
#else
 LAYOUT(struct Library,OFF(struct Library,lib_Node),OFF(struct Library,lib_Flags),OFF(struct Library,lib_pad),OFF(struct Library,lib_NegSize),OFF(struct Library,lib_PosSize),OFF(struct Library,lib_Version),OFF(struct Library,lib_Revision),OFF(struct Library,lib_IdString),OFF(struct Library,lib_Sum),OFF(struct Library,lib_OpenCnt),OFF(struct Library,lib_Pad)),
#endif
 LAYOUT(struct Message,OFF(struct Message,mn_Node),OFF(struct Message,mn_ReplyPort),OFF(struct Message,mn_Length)),
 LAYOUT(struct List,OFF(struct List,lh_Head),OFF(struct List,lh_Tail),OFF(struct List,lh_TailPred),OFF(struct List,lh_Type),OFF(struct List,l_pad)),
#ifdef AMI_RUST_ABI11
 LAYOUT(struct MsgPort,OFF(struct MsgPort,mp_Node),OFF(struct MsgPort,mp_Flags),OFF(struct MsgPort,mp_SigBit),OFF(struct MsgPort,mp_SigTask),OFF(struct MsgPort,mp_MsgList),OFF(struct MsgPort,mp_Private)),
#else
 LAYOUT(struct MsgPort,OFF(struct MsgPort,mp_Node),OFF(struct MsgPort,mp_Flags),OFF(struct MsgPort,mp_SigBit),OFF(struct MsgPort,mp_SigTask),OFF(struct MsgPort,mp_MsgList),OFF(struct MsgPort,mp_Pad)),
#endif
 LAYOUT(struct FileInfoBlock,OFF(struct FileInfoBlock,fib_DiskKey),OFF(struct FileInfoBlock,fib_DirEntryType),OFF(struct FileInfoBlock,fib_FileName),OFF(struct FileInfoBlock,fib_Protection),OFF(struct FileInfoBlock,fib_EntryType),OFF(struct FileInfoBlock,fib_Size),OFF(struct FileInfoBlock,fib_NumBlocks),OFF(struct FileInfoBlock,fib_Date),OFF(struct FileInfoBlock,fib_Comment),OFF(struct FileInfoBlock,fib_OwnerUID),OFF(struct FileInfoBlock,fib_OwnerGID),OFF(struct FileInfoBlock,fib_Reserved)),
 sizeof(IPTR),_Alignof(IPTR),sizeof(BPTR),_Alignof(BPTR),sizeof(LONG),_Alignof(LONG),sizeof(ULONG),_Alignof(ULONG),
#ifndef AMI_RUST_ABI11
 LAYOUT(spinlock_t,OFF(spinlock_t,s_Owner),OFF(spinlock_t,s_Isolation)),
#endif
 LAYOUT(SdkError,OFF(SdkError,kind),OFF(SdkError,native)),
 LAYOUT(SdkStats,OFF(SdkStats,blocks),OFF(SdkStats,backing_charge),OFF(SdkStats,peak_charge),OFF(SdkStats,files),OFF(SdkStats,libraries),OFF(SdkStats,ports),OFF(SdkStats,signals),OFF(SdkStats,messages),OFF(SdkStats,refusals),OFF(SdkStats,devices),OFF(SdkStats,requests),OFF(SdkStats,directories)),
 LAYOUT(SdkEntry,OFF(SdkEntry,size),OFF(SdkEntry,protection),OFF(SdkEntry,name_length),OFF(SdkEntry,entry_type),OFF(SdkEntry,directory_type),OFF(SdkEntry,days),OFF(SdkEntry,minutes),OFF(SdkEntry,ticks),OFF(SdkEntry,name))
};
/* Timer types of the selected SDK: timerequest carries struct timeval on
   ABI-v1 and struct timeval32 on ABI-v11; both are two 32-bit fields. */
static const size_t c_timer_layout[]={
 sizeof(struct timerequest),_Alignof(struct timerequest),OFF(struct timerequest,tr_time),
 sizeof(struct EClockVal),OFF(struct EClockVal,ev_lo),
 sizeof(((struct timerequest*)0)->tr_time),
 OFF(__typeof__(((struct timerequest*)0)->tr_time),tv_micro),
 sizeof(struct IORequest)
};
size_t sdk_timer_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_timer_layout)/sizeof(*c_timer_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_timer_layout[i];return count;
}
size_t sdk_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_layout)/sizeof(*c_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_layout[i];return count;
}

uint64_t sdk_scalar(int32_t s,uint32_t u,uintptr_t p,uint64_t w,size_t n) {
 return ((uint64_t)(uint32_t)s<<32)^(uint64_t)u^(uint64_t)p^w^(uint64_t)n;
}
