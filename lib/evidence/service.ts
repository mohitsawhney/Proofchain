import type { DeviceKey, Evidence, FileAnalysis, ProofBundle, EventType } from '@/types/proofchain';
import { evidenceSchema, makeEvent, pack, publicOnly, verifyFullCustodyChain } from '@/lib/crypto/core';
import { appendLocalProof, listLocalProofs, localRead } from './local-store';
import { getCloudProof, listCloudEvidence, registerPublicKey, saveCloudProof } from '@/lib/firebase/repository';
export async function listEvidence(uid:string, cloud:boolean):Promise<Evidence[]> {
 const items=cloud?await listCloudEvidence(uid):(await listLocalProofs()).filter(p=>p.evidence.ownerId===uid || p.custodyEvents.some(e=>e.toUserId===uid)).map(p=>p.evidence);
 return items.sort((a,b)=>b.registeredAt.localeCompare(a.registeredAt));
}
export async function getProof(id:string,cloud:boolean):Promise<ProofBundle>{
 if(!/^[A-Za-z0-9_-]{1,160}$/.test(id))throw new Error('Enter a valid evidence ID.');
 if(cloud)return getCloudProof(id);
 const proof=await localRead<ProofBundle>('proofs',id);if(!proof)throw new Error('This evidence is not in the local workspace. Import its proof bundle or sign in to look up a Firebase record.');return proof;
}
export async function registerEvidence(analysis:FileAnalysis,title:string,description:string,key:DeviceKey,cloud:boolean,includeFingerprint:boolean):Promise<ProofBundle>{
 const evidence=evidenceSchema.parse({id:'EV-'+crypto.randomUUID().replaceAll('-','').toUpperCase(),title:title.trim(),description:description.trim(),sha256:analysis.sha256,fileSize:analysis.size,mimeType:analysis.mimeType,ownerId:key.userId,registeredAt:new Date().toISOString(),perceptualHash:includeFingerprint?analysis.perceptualHash:null,c2paStatus:analysis.c2pa.status,scope:cloud?'firebase':'local'});
 const event=await makeEvent(evidence,key,[],'REGISTER',null,analysis.sha256);
 const proof=pack(evidence,[event],[publicOnly(key)]);
 if(cloud){await registerPublicKey(publicOnly(key));await saveCloudProof(proof);}else await appendLocalProof(proof);
 return proof;
}
export async function appendEvent(proof:ProofBundle,type:EventType,key:DeviceKey,to:string|null=null,digest:string|null=null):Promise<ProofBundle>{
 const checked=await verifyFullCustodyChain(proof);if(!checked.valid)throw new Error('The existing custody chain is invalid. No event was added.');
 if(type==='RECEIVE' && digest!==proof.evidence.sha256)throw new Error('Exact match failed. Custody cannot be accepted.');
 const event=await makeEvent(proof.evidence,key,proof.custodyEvents,type,to,digest);
 const keys=proof.publicKeys.some(k=>k.keyId===key.keyId)?proof.publicKeys:[...proof.publicKeys,publicOnly(key)];
 const next=pack(proof.evidence,[...proof.custodyEvents,event],keys);
 if(!(await verifyFullCustodyChain(next)).valid)throw new Error('This custody action is not permitted for the current account or transfer state.');
 if(proof.evidence.scope==='firebase'){await registerPublicKey(publicOnly(key));await saveCloudProof(next,proof.checkpoint.headHash);}else await appendLocalProof(next,proof.checkpoint.headHash);
 return next;
}
export function downloadJson(proof:ProofBundle){
 const url=URL.createObjectURL(new Blob([JSON.stringify(proof,null,2)],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download=proof.evidence.id+'.proofchain.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
