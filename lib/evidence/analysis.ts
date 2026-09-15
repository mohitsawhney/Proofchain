import type { FileAnalysis } from '@/types/proofchain';
export async function inspectMetadata(file:File):Promise<Pick<FileAnalysis,'metadata'|'metadataMessage'|'perceptualHash'>>{
 const metadata:Record<string,string>={};let message='Advanced image analysis is unavailable for this file type.',fingerprint:string|null=null;
 if(!['image/jpeg','image/png','image/webp','image/tiff','image/heic'].includes(file.type)) return {metadata,metadataMessage:message,perceptualHash:null};
 if(file.size>20*1024*1024)return {metadata,metadataMessage:'Advanced image parsing is limited to 20 MB. Exact hashing has no such limit.',perceptualHash:null};
 try {
  const exifr=await import('exifr');
  const parsed=await exifr.parse(file,{pick:['Make','Model','DateTimeOriginal','Software','Orientation','ExifImageWidth','ExifImageHeight'],gps:false,translateValues:true}) as Record<string,unknown>|undefined;
  if(parsed)for(const [key,value] of Object.entries(parsed))if(value!==undefined && value!==null)metadata[key]=value instanceof Date?value.toISOString():String(value).slice(0,300);
  message=Object.keys(metadata).length?'Reported metadata is editable and is not independently authenticated.':'No supported EXIF fields found. This says nothing about authenticity.';
  const width=Number(parsed?.ExifImageWidth||0),height=Number(parsed?.ExifImageHeight||0);
  if(width*height>40_000_000)return {metadata,metadataMessage:message+' Similarity skipped for this image size.',perceptualHash:null};
  const bitmap=await createImageBitmap(file,{resizeWidth:9,resizeHeight:8});
  const canvas=document.createElement('canvas');canvas.width=9;canvas.height=8;
  const context=canvas.getContext('2d');if(!context){bitmap.close();return {metadata,metadataMessage:message,perceptualHash:null};}
  context.drawImage(bitmap,0,0,9,8);bitmap.close();const pixels=context.getImageData(0,0,9,8).data;
  let bits='';const gray=(i:number)=>pixels[i]*0.299+pixels[i+1]*0.587+pixels[i+2]*0.114;
  for(let y=0;y<8;y++)for(let x=0;x<8;x++)bits+=gray((y*9+x)*4)>gray((y*9+x+1)*4)?'1':'0';
  fingerprint=Array.from({length:16},(_,i)=>parseInt(bits.slice(i*4,i*4+4),2).toString(16)).join('');
 }catch{message='Metadata could not be parsed. Exact SHA-256 verification is still available.';}
 return {metadata,metadataMessage:message,perceptualHash:fingerprint};
}
export function hammingDistance(a:string,b:string):number|null {
 if(!/^[a-f0-9]{16}$/.test(a)||!/^[a-f0-9]{16}$/.test(b))return null;
 let distance=0;for(let i=0;i<16;i++){let n=parseInt(a[i],16)^parseInt(b[i],16);while(n){distance+=n&1;n>>=1;}}return distance;
}
export async function inspectCredentials(file:File):Promise<FileAnalysis['c2pa']>{
 if(file.size>25*1024*1024)return {status:'Not analysed',detail:'Local C2PA inspection is limited to 25 MB; exact hashing remains available.'};
 const {createC2pa}=await import('@contentauth/c2pa-web');
 let sdk:Awaited<ReturnType<typeof createC2pa>>|undefined,timer:ReturnType<typeof setTimeout>|undefined,expired=false;
 try {
  return await Promise.race([(async()=>{
   const basePath=process.env.NEXT_PUBLIC_BASE_PATH||'';
   sdk=await createC2pa({wasmSrc:`${basePath}/c2pa/c2pa_bg.wasm`,settings:{verify:{remoteManifestFetch:false,ocspFetch:false,verifyAfterReading:true,verifyTrust:false}}});
   if(expired){sdk.dispose();throw new Error('Inspection timeout.');}
   const reader=await sdk.reader.fromBlob(file.type||'application/octet-stream',file);
   if(!reader)return {status:'No embedded credentials',detail:'No embedded Content Credentials detected. Remote lookup is disabled. Absence does not mean the file is fake.'};
   try {
    const store=await reader.manifestStore(),manifest=await reader.activeManifest();
    const failed=store.validation_state==='Invalid';
    return {status:failed?'Validation failed':store.validation_state==='Valid' || store.validation_state==='Trusted'?'Embedded binding valid':'Credentials detected',detail:failed?'The C2PA SDK reported invalid credentials.':'Embedded validation only. Issuer trust, remote manifests and online revocation are not established.',issuer:manifest.signature_info?.issuer ?? undefined};
   }finally{await reader.free();}
  })(),new Promise<FileAnalysis['c2pa']>((resolve)=>{timer=setTimeout(()=>{expired=true;sdk?.dispose();resolve({status:'Analysis unavailable',detail:'C2PA inspection timed out. Exact file integrity is still available.'});},20000);})]);
 }catch{return {status:'Analysis unavailable',detail:'Content Credentials could not be analysed for this file or browser. No authenticity conclusion can be drawn.'};}
 finally{clearTimeout(timer);sdk?.dispose();}
}
