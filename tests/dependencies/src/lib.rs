#![no_std]
extern crate alloc;
use alloc::{collections::BTreeMap,string::String};
use aros_runtime::{AppStatus,Context};
fn check(v:bool)->Result<(),i32>{if v{Ok(())}else{Err(20)}}
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
struct DerivedProbe { marker: String, values: alloc::vec::Vec<u32> }
fn dependencies()->Result<(),i32>{
 let original=DerivedProbe{marker:String::from("AROS"),values:alloc::vec![0,1,255]};
 let encoded=serde_json::to_vec(&original).map_err(|_|20)?;
 check(encoded==br#"{"marker":"AROS","values":[0,1,255]}"#)?;
 let restored:DerivedProbe=serde_json::from_slice(&encoded).map_err(|_|20)?;
 check(restored==original)?;
 check(serde_json::from_slice::<DerivedProbe>(br#"{"marker":"AROS","values":[0,1,"bad"]}"#).is_err())?;
 let mut m=BTreeMap::new();for i in 0..16{let k=alloc::format!("k{:02}",i);m.insert(k,i);}
 let bytes=serde_json::to_vec(&m).map_err(|_|20)?;check(bytes.len()==135)?;
 let decoded:BTreeMap<String,i32>=serde_json::from_slice(&bytes).map_err(|_|20)?;check(decoded==m)?;
 let again=serde_json::to_vec(&decoded).map_err(|_|20)?;check(again==bytes)?;
 check(serde_json::from_slice::<BTreeMap<String,i32>>(&bytes[..bytes.len()-1]).is_err())?;
 fn hex<const N:usize>(s:&[u8])->[u8;N]{let mut a=[0;N];fn d(b:u8)->u8{if b<=b'9'{b-b'0'}else{b-b'a'+10}}for i in 0..N{a[i]=d(s[i*2])*16+d(s[i*2+1]);}a}
 let pk=hex::<32>(b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
 let sig=hex::<64>(b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
 let key=ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_|20)?;let good=ed25519_dalek::Signature::from_bytes(&sig);let mut bad=sig;bad[0]^=1;let bad=ed25519_dalek::Signature::from_bytes(&bad);
 for _ in 0..50{check(key.verify_strict(b"",&good).is_ok())?;check(key.verify_strict(b"",&bad).is_err())?;}
 Ok(())
}
fn application(ctx:&Context)->AppStatus {
 let status=dependencies();
 if status.is_ok(){ctx.diagnostic(b"JSON135 Ed25519 50-pairs Serde-derive",100);AppStatus::Success}else{AppStatus::Fatal}
}
aros_runtime::entry!(application,alloc);
