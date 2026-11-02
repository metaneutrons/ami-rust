/* Independent native-header layout oracle, not a Rust-derived expected table. */
#include "sdk.h"
#include <exec/ports.h>
#include <exec/libraries.h>
#include <dos/dosextens.h>
#include <devices/timer.h>
#include <intuition/intuition.h>
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
 LAYOUT(SdkStats,OFF(SdkStats,blocks),OFF(SdkStats,backing_charge),OFF(SdkStats,peak_charge),OFF(SdkStats,files),OFF(SdkStats,libraries),OFF(SdkStats,ports),OFF(SdkStats,signals),OFF(SdkStats,messages),OFF(SdkStats,refusals),OFF(SdkStats,devices),OFF(SdkStats,requests),OFF(SdkStats,directories),OFF(SdkStats,rastports),OFF(SdkStats,bitmaps),OFF(SdkStats,windows),OFF(SdkStats,pubscreens),OFF(SdkStats,aslrequests),OFF(SdkStats,locales),OFF(SdkStats,catalogs)),
 LAYOUT(SdkEntry,OFF(SdkEntry,size),OFF(SdkEntry,protection),OFF(SdkEntry,name_length),OFF(SdkEntry,entry_type),OFF(SdkEntry,directory_type),OFF(SdkEntry,days),OFF(SdkEntry,minutes),OFF(SdkEntry,ticks),OFF(SdkEntry,size_exact),OFF(SdkEntry,name))
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
/* The window and event records of the bridge and the tag, IDCMP and message
   code values the Rust window API relies on. */
static const size_t c_intui_layout[]={
 sizeof(SdkWindowInfo),_Alignof(SdkWindowInfo),OFF(SdkWindowInfo,signal_mask),OFF(SdkWindowInfo,rastport),
 sizeof(SdkIntuiEvent),OFF(SdkIntuiEvent,x),OFF(SdkIntuiEvent,micros),
 WA_Left,WA_Top,WA_Width,WA_Height,WA_IDCMP,WA_Title,WA_MinWidth,WA_MinHeight,WA_MaxWidth,WA_MaxHeight,
 WA_InnerWidth,WA_InnerHeight,WA_PubScreen,WA_SizeGadget,WA_DragBar,WA_DepthGadget,WA_CloseGadget,
 WA_ReportMouse,WA_Borderless,WA_Activate,WA_SimpleRefresh,WA_SmartRefresh,WA_GimmeZeroZero,
 IDCMP_NEWSIZE,IDCMP_REFRESHWINDOW,IDCMP_MOUSEBUTTONS,IDCMP_MOUSEMOVE,IDCMP_CLOSEWINDOW,IDCMP_RAWKEY,
 IDCMP_VANILLAKEY,IDCMP_ACTIVEWINDOW,IDCMP_INACTIVEWINDOW,
 SELECTDOWN,SELECTUP,MENUDOWN,MENUUP,MIDDLEDOWN,MIDDLEUP
};
size_t sdk_intui_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_intui_layout)/sizeof(*c_intui_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_intui_layout[i];return count;
}
/* The asl.library file requester: the bridge's view of the FileRequester and
   the tags the Rust requester builder uses. The pinned ABI-v11 C SDK has no
   asl header; its values are those of the ABI-v11 SDK's libraries/asl.h, which
   are identical to the ABI-v1 header. */
#ifdef AMI_RUST_ABI11
#define ASL_TB (TAG_USER + 0x80000)
#define ASL_FileRequest 0
#define ASLFR_TitleText (ASL_TB + 1)
#define ASLFR_Window (ASL_TB + 2)
#define ASLFR_InitialLeftEdge (ASL_TB + 3)
#define ASLFR_InitialTopEdge (ASL_TB + 4)
#define ASLFR_InitialWidth (ASL_TB + 5)
#define ASLFR_InitialHeight (ASL_TB + 6)
#define ASLFR_InitialFile (ASL_TB + 8)
#define ASLFR_InitialDrawer (ASL_TB + 9)
#define ASLFR_InitialPattern (ASL_TB + 10)
#define ASLFR_PositiveText (ASL_TB + 18)
#define ASLFR_NegativeText (ASL_TB + 19)
#define ASLFR_SleepWindow (ASL_TB + 43)
#define ASLFR_DoSaveMode (ASL_TB + 44)
#define ASLFR_DoMultiSelect (ASL_TB + 45)
#define ASLFR_DoPatterns (ASL_TB + 46)
#define ASLFR_DrawersOnly (ASL_TB + 47)
#define ASLFR_RejectIcons (ASL_TB + 60)
#define ASLFR_PopToFront (ASL_TB + 131)
#define ASLFR_Activate (ASL_TB + 132)
#else
#include <libraries/asl.h>
#endif
static const size_t c_asl_layout[]={
 ASL_FileRequest,ASLFR_TitleText,ASLFR_Window,ASLFR_InitialLeftEdge,ASLFR_InitialTopEdge,
 ASLFR_InitialWidth,ASLFR_InitialHeight,ASLFR_InitialFile,ASLFR_InitialDrawer,ASLFR_InitialPattern,
 ASLFR_PositiveText,ASLFR_NegativeText,ASLFR_SleepWindow,ASLFR_DoSaveMode,ASLFR_DoMultiSelect,
 ASLFR_DoPatterns,ASLFR_DrawersOnly,ASLFR_RejectIcons,ASLFR_PopToFront,ASLFR_Activate
};
size_t sdk_asl_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_asl_layout)/sizeof(*c_asl_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_asl_layout[i];return count;
}
/* locale.library: the catalog tags and string numbers the Rust API uses. The
   pinned ABI-v11 C SDK has no locale header; its values are those of the
   ABI-v11 SDK's libraries/locale.h and localestd.h, identical to ABI-v1. */
#ifdef AMI_RUST_ABI11
#define OC_TagBase (TAG_USER + 0x90000)
#define OC_BuiltInLanguage (OC_TagBase + 1)
#define OC_Version (OC_TagBase + 3)
#define OC_Language (OC_TagBase + 4)
#define DAY_1 1
#define ABDAY_1 8
#define MON_1 15
#define ABMON_1 27
#define YESSTR 39
#define NOSTR 40
#define AM_STR 41
#define PM_STR 42
#else
#include <libraries/locale.h>
#endif
static const size_t c_locale_layout[]={
 OC_BuiltInLanguage,OC_Version,OC_Language,DAY_1,ABDAY_1,MON_1,ABMON_1,YESSTR,NOSTR,AM_STR,PM_STR,
 sizeof(SdkLocaleInfo),OFF(SdkLocaleInfo,language_name),OFF(SdkLocaleInfo,preferred),OFF(SdkLocaleInfo,gmt_offset)
};
size_t sdk_locale_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_locale_layout)/sizeof(*c_locale_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_locale_layout[i];return count;
}
size_t sdk_layout(uint64_t *out,size_t cap) {
 const size_t count=sizeof(c_layout)/sizeof(*c_layout);
 if(cap<count || !out)return count;
 for(size_t i=0;i<count;i++)out[i]=c_layout[i];return count;
}

uint64_t sdk_scalar(int32_t s,uint32_t u,uintptr_t p,uint64_t w,size_t n) {
 return ((uint64_t)(uint32_t)s<<32)^(uint64_t)u^(uint64_t)p^w^(uint64_t)n;
}
