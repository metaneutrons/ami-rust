from pathlib import Path
import struct,json,hashlib,sys
ALLOWED={0,1,2,4,10,11,24,25}
def audit(path,variant):
 p=Path(path);b=p.read_bytes();assert b[:9]==b'\x7fELF\x02\x01\x01\x0f\x01','wrong ELF identity/ABI marker';assert len(b)>=64
 et,machine=struct.unpack_from('<HH',b,16);assert(et,machine)==(1,62),'wrong native ET_REL/x86_64'
 off=struct.unpack_from('<Q',b,40)[0];size,count,strings=struct.unpack_from('<HHH',b,58);assert size==64 and 0<count<65535 and strings<count and off+count*size<=len(b),'bad section header bounds'
 sh=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*size)for i in range(count)];tab=sh[strings];assert tab[4]+tab[5]<=len(b);names=b[tab[4]:tab[4]+tab[5]]
 def name(x):return names[x[0]:].split(b'\0')[0].decode(errors='replace')
 def sectiondata(x):
  if x[1]==8:return b''
  assert x[4]+x[5]<=len(b),'bad section data range';return b[x[4]:x[4]+x[5]]
 for x in sh:sectiondata(x)
 alloc=[(i,x)for i,x in enumerate(sh)if x[2]&2 and x[5]];assert alloc and alloc[0][1][2]&4,'first allocated hunk is not executable'
 symbols={};strong_undefined=[];strong_definitions=set()
 for i,x in enumerate(sh):
  if x[1]!=2:continue
  assert x[9]==24 and x[6]<count and x[5]%24==0,'invalid symbols';st=sectiondata(sh[x[6]]);syms=[]
  for at in range(x[4],x[4]+x[5],24):
   n,info,other,index,value,sz=struct.unpack_from('<IBBHQQ',b,at);nm=st[n:].split(b'\0')[0].decode(errors='replace');syms.append({'name':nm,'info':info,'other':other,'section':index,'value':value,'size':sz})
   if index==0 and info>>4==1 and nm:strong_undefined.append(nm)
   if index!=0 and info>>4==1 and nm:
    assert nm not in strong_definitions,('duplicate strong definition',nm)
    strong_definitions.add(nm)
  symbols[i]=syms
 assert not strong_undefined,('unresolved strong symbols',strong_undefined)
 entries=[s for a in symbols.values()for s in a if s['name']=='__startup_entry'];assert len(entries)==1 and entries[0]['section']==alloc[0][0] and entries[0]['value']==0,'startup mustenter firsttext at0'
 relocs=[];types={}
 for i,x in enumerate(sh):
  if x[1]!=4:continue
  assert x[9]==24 and x[5]%24==0 and x[6]in symbols and x[7]<count,'invalid RELA table'
  if not sh[x[7]][2]&2:continue
  for at in range(x[4],x[4]+x[5],24):
   dest,info,add=struct.unpack_from('<QQq',b,at);typ=info&0xffffffff;idx=info>>32;assert typ in ALLOWED,('unsupported AROS relocation',typ);assert idx<len(symbols[x[6]]),'invalid relocation symbol';width=4 if typ in [2,4,10,11]else 8 if typ else 0
   assert dest+width<=sh[x[7]][5],'relocation outofbounds';s=symbols[x[6]][idx];relocs.append({'target_section':name(sh[x[7]]),'offset':dest,'type':typ,'addend':add,'symbol_section':s['section'],'symbol_value':s['value'],'symbol_name':s['name']});types[typ]=types.get(typ,0)+1
 rows=[{'index':i,'name':name(x),'type':x[1],'flags':x[2],'size':x[5],'align':x[8],'sha256':hashlib.sha256(sectiondata(x)).hexdigest()}for i,x in alloc]
 code_ro=sum(x['size']for x in rows if not x['flags']&1);writable=sum(x['size']for x in rows if x['flags']&1);allocated_static=code_ro+writable;static_owned=allocated_static+131072;maxfile=1048576 if variant=='core'else 4194304;maxcode=524288 if variant=='core'else 2097152
 observations={'file':len(b)<=maxfile,'code_ro':code_ro<=maxcode,'static_owned':static_owned<=33554432};limits={'file':maxfile,'code_ro':maxcode,'static_owned':33554432}
 return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'file_bytes':len(b),'variant':variant,'code_ro_bytes':code_ro,'writable_bss_bytes':writable,'allocated_static_bytes':allocated_static,'static_owned_estimate_bytes':static_owned,'allocated_sections':rows,'entry':entries[0],'relocation_types':types,'relocations':relocs,'strong_undefined':strong_undefined,'limits':limits,'limits_are_product_constraints':False,'limits_scope':'reference-test-thresholds','reference_status':{'within_reference_limits':all(observations.values()),'observations':{k:'within-reference-threshold' if v else 'above-reference-threshold' for k,v in observations.items()}},'result':'PASS'}
if __name__=='__main__':
 try:d=audit(sys.argv[1],sys.argv[2]);Path(sys.argv[3]).write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({k:v for k,v in d.items()if k not in ['allocated_sections','relocations']},indent=2))
 except Exception as e:print(type(e).__name__+': '+str(e));sys.exit(1)
