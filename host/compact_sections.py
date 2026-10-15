"""Compact only internal Rust section-name metadata before native audit.

ELF payload, section index/type/flags/alignment and symbol/relocation tables are
preserved. The AROS loader's special section names and startup symbol stay intact.
This is part of the frozen recipe, never normalization of a failed byte replay.
"""
from pathlib import Path
import sys,struct,json,hashlib

def compact(source,destination,receipt):
 b=bytearray(Path(source).read_bytes());assert b[:4]==b'\x7fELF'
 assert struct.unpack_from('<HH',b,16)==(1,62)
 assert struct.unpack_from('<H',b,56)[0]==0,'unexpected program header'
 shoff=struct.unpack_from('<Q',b,40)[0];entsize,count,idx=struct.unpack_from('<HHH',b,58);assert entsize==64
 sh=[list(struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*64))for i in range(count)]
 tab=sh[idx];oldoff,oldsize=tab[4],tab[5];assert oldoff+oldsize<=len(b)
 names=bytes(b[oldoff:oldoff+oldsize]);new=bytearray(b'\0');renamed=[];payloads=[]
 for i,x in enumerate(sh):
  name=names[x[0]:].split(b'\0')[0].decode();label=name
  rust_symbol='._R' in name and name.startswith(('.ltext.','.lrodata.','.ldata.','.lbss.','.rela.ltext.','.rela.lrodata.','.rela.ldata.','.rela.lbss.'))
  # LLVM 23 also emits long private constant section names in the large
  # code model. Shorten only this explicit compiler-local family. AROS special
  # section names, all indices, flags, symbols and relocation payloads stay.
  rust_local_constant=name.startswith(('.lrodata..Lanon.','.rela.lrodata..Lanon.'))
  if rust_symbol or rust_local_constant:
   label='.r'+str(i);renamed.append({'section':i,'from':name,'to':label})
  x[0]=len(new)if label else 0
  if label:new+=label.encode()+b'\0'
  if i!=idx and x[1]!=8:
   payloads.append((i,hashlib.sha256(b[x[4]:x[4]+x[5]]).hexdigest()))
 assert len(new)<=oldsize,'metadata expansion'
 # Preserve all subsequent file offsets' alignment by shrinking in multiples8.
 padded=bytes(new)+b'\0'*((oldsize-len(new))%8);delta=oldsize-len(padded)
 assert delta>=0 and delta%8==0 and shoff>=oldoff+oldsize
 b[oldoff:oldoff+oldsize]=padded;newshoff=shoff-delta
 struct.pack_into('<Q',b,40,newshoff)
 for i,x in enumerate(sh):
  if i==idx:x[5]=len(new)
  elif x[4]>=oldoff+oldsize:x[4]-=delta
  assert x[8] in (0,1) or x[4]%x[8]==0,('section file alignment changed',i,x[8])
  struct.pack_into('<IIQQQQIIQQ',b,newshoff+i*64,*x)
 for i,sha in payloads:
  x=sh[i];assert hashlib.sha256(b[x[4]:x[4]+x[5]]).hexdigest()==sha,('payload changed',i)
 Path(destination).write_bytes(b)
 record={'input':str(source),'output':str(destination),'input_bytes':len(b)+delta,'output_bytes':len(b),'saved_metadata_bytes':delta,'sections_renamed':len(renamed),'all_other_section_payloads_preserved':True,'renames':renamed}
 Path(receipt).write_text(json.dumps(record,indent=2)+'\n');print('section metadata bytes saved',delta)
if __name__=='__main__':compact(*sys.argv[1:])
