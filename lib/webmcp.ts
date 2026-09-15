import {parseBundle,verifyFullCustodyChain} from '@/lib/crypto/core';
interface ModelContext {registerTool(tool:{name:string;description:string;inputSchema:object;annotations:{readOnlyHint:boolean;untrustedContentHint:boolean};execute:(input:unknown)=>Promise<unknown>},options:{signal:AbortSignal}):void|Promise<void>}
export function registerAgentTools(){
 const context=(document as Document & {modelContext?:ModelContext}).modelContext;if(!context?.registerTool)return;
 const lifecycle=new AbortController();
 try{void Promise.resolve(context.registerTool({name:'verify_proofchain_bundle',description:'Locally verify the structure, hashes, custody rules and signatures of a supplied ProofChain JSON bundle. Does not compare a file, contact Firebase or establish issuer identity.',inputSchema:{type:'object',properties:{bundle:{type:'object'}},required:['bundle'],additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute:async(input)=>{
  if(!input||typeof input!=='object'||Object.keys(input).length!==1||!('bundle'in input))throw new Error('Expected a bundle object.');
  const proof=parseBundle(input.bundle),result=await verifyFullCustodyChain(proof);
  return {evidenceId:proof.evidence.id,valid:result.valid,hashChainValid:result.hashChainValid,signaturesValid:result.signaturesValid,failures:result.checks.filter(c=>!c.valid),scope:'Supplied bundle only; no exact-file or identity claim.'};
 }},{signal:lifecycle.signal})).catch(()=>{});}catch{/* An unsupported agent API must not interfere with normal verification. */}
 return ()=>lifecycle.abort();
}
