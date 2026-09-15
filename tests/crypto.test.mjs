import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createSHA256} from 'hash-wasm';
import {canonical,sha256,generateDeviceKey,makeEvent,pack,publicOnly,verifyFullCustodyChain,parseBundle,verifyEventSignature,eventPayload} from '../lib/crypto/core.ts';
const data='ProofChain test bytes\n';
async function fixture(){const alice=await generateDeviceKey('alice'),bob=await generateDeviceKey('bob');const digest=await sha256(data);const evidence={id:'EV-test',title:'Test evidence',description:'',sha256:digest,fileSize:data.length,mimeType:'text/plain',ownerId:'alice',registeredAt:new Date().toISOString(),perceptualHash:null,c2paStatus:'Not analysed',scope:'local'};const r=await makeEvent(evidence,alice,[],'REGISTER',null,digest),t=await makeEvent(evidence,alice,[r],'TRANSFER','bob'),v=await makeEvent(evidence,bob,[r,t],'RECEIVE',null,digest);return {alice,bob,evidence,proof:pack(evidence,[r,t,v],[publicOnly(alice),publicOnly(bob)])};}
const base=await fixture();
test('SHA-256 known vector and arbitrary binary chunking',async()=>{assert.equal(await sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');const b=new Uint8Array(9*1024*1024+3);for(let i=0;i<b.length;i++)b[i]=i%251;const h=await createSHA256();h.init();for(let i=0;i<b.length;i+=4*1024*1024)h.update(b.subarray(i,i+4*1024*1024));assert.equal(h.digest('hex'),await sha256(b.buffer));});
test('Original, renamed and copied files match',async()=>{const a=new File([data],'a.txt'),b=new File([data],'renamed.bin'),c=new File([a],'copy');assert.equal(await sha256(await a.arrayBuffer()),await sha256(await b.arrayBuffer()));assert.equal(await sha256(await a.arrayBuffer()),await sha256(await c.arrayBuffer()));});
test('A one-byte edit fails exact identity',async()=>{assert.notEqual(await sha256(data),await sha256(data.replace('bytes','byteS')));});
test('Canonicalization is independent of insertion order and handles Unicode',()=>{assert.equal(canonical({b:2,a:1}),canonical({a:1,b:2}));assert.equal(canonical({'€':'भारत',z:[1,true,null]}),canonical({z:[1,true,null],'€':'भारत'}));});
test('Private keys are not exportable',async()=>{assert.equal(base.alice.privateKey.extractable,false);await assert.rejects(crypto.subtle.exportKey('jwk',base.alice.privateKey));assert.equal('privateKey'in publicOnly(base.alice),false);});
test('Valid register/transfer/receive sequence passes',async()=>{const r=await verifyFullCustodyChain(base.proof);assert.equal(r.valid,true);assert.equal(r.currentCustodian,'bob');assert.equal(r.pendingRecipient,null);});
test('Correct verification event passes',async()=>{const e=await makeEvent(base.evidence,base.bob,base.proof.custodyEvents,'VERIFY',null,base.evidence.sha256);assert.equal((await verifyFullCustodyChain(pack(base.evidence,[...base.proof.custodyEvents,e],base.proof.publicKeys))).valid,true);});
test('Incorrect received file is rejected even with a real signature',async()=>{const p=structuredClone(base.proof);p.custodyEvents[2]=await makeEvent(base.evidence,base.bob,p.custodyEvents.slice(0,2),'RECEIVE',null,await sha256('wrong'));p.checkpoint.headHash=p.custodyEvents[2].eventHash;assert.equal((await verifyFullCustodyChain(p)).valid,false);});
for(const [name,mutate] of [
 ['altered event',p=>{p.custodyEvents[1].toUserId='attacker';}],
 ['forged signature',p=>{p.custodyEvents[0].signature=btoa('x'.repeat(64));}],
 ['missing interior event',p=>{p.custodyEvents.splice(1,1);}],
 ['reordered history',p=>{p.custodyEvents.reverse();}],
 ['wrong public key',p=>{p.publicKeys[0].publicKey=base.bob.publicKey;}],
 ['replaced public key owner',p=>{p.publicKeys[0].userId='mallory';}],
 ['modified evidence title',p=>{p.evidence.title='Changed';}],
 ['modified evidence digest',p=>{p.evidence.sha256='f'.repeat(64);}],
 ['deleted ending against retained checkpoint',p=>{p.custodyEvents.pop();}],
 ['duplicate event',p=>{p.custodyEvents.push(p.custodyEvents[2]);}],
 ['unknown signed payload field',p=>{p.custodyEvents[0].hidden='payload';}],
 ['private key in exported JWK',p=>{p.publicKeys[0].publicKey.d='private';}]
])test(name+' fails verification',async()=>{const p=structuredClone(base.proof);mutate(p);assert.equal((await verifyFullCustodyChain(p)).valid,false);});
test('Recomputed event hashes cannot repair a broken signature',async()=>{const p=structuredClone(base.proof);p.custodyEvents[1].toUserId='mallory';p.custodyEvents[1].eventHash=await sha256(canonical(eventPayload(p.custodyEvents[1])));assert.equal(await verifyEventSignature(p.custodyEvents[1],p.publicKeys[0]),false);});
test('Unauthorized sender with real key is rejected',async()=>{const p=base.proof;const bad=await makeEvent(base.evidence,base.alice,p.custodyEvents,'TRANSFER','charlie');assert.equal((await verifyFullCustodyChain(pack(base.evidence,[...p.custodyEvents,bad],p.publicKeys))).valid,false);});
test('Changing only serialization ordering preserves a bundle',async()=>{const p=JSON.parse(JSON.stringify(base.proof));p.evidence=Object.fromEntries(Object.entries(p.evidence).reverse());assert.equal((await verifyFullCustodyChain(p)).valid,true);});
test('Known limitation: replacing checkpoint hides tail truncation',async()=>{const p=structuredClone(base.proof);p.custodyEvents.pop();p.checkpoint={headHash:p.custodyEvents.at(-1).eventHash,eventCount:2};assert.equal((await verifyFullCustodyChain(p)).valid,true,'An independent checkpoint is needed to establish freshness.');});
test('Malformed bundle is rejected at the boundary',()=>{assert.throws(()=>parseBundle({}));assert.throws(()=>parseBundle({...base.proof,proofChainVersion:'2'}));});
for(const name of ['recompressed','metadata-change','pixel-change','watermarked'])test(name+' PNG fails exact match',async()=>{const {readFile}=await import('node:fs/promises');const original=await readFile(new URL('./fixtures/original.png',import.meta.url)),altered=await readFile(new URL('./fixtures/'+name+'.png',import.meta.url));const h1=await createSHA256(),h2=await createSHA256();h1.init();h2.init();h1.update(original);h2.update(altered);assert.notEqual(h1.digest('hex'),h2.digest('hex'));});
test('Malformed EXIF does not prevent complete-byte hashing',async()=>{const {default:exifr}=await import('exifr');const raw=Uint8Array.from([255,216,255,225,0,16,69,120,105,102,0,0,255,255,0,0]);try{await exifr.parse(raw);}catch{/* Metadata parsing is best-effort. */}const h=await createSHA256();h.init();h.update(raw);assert.equal(h.digest('hex'),await sha256(raw.buffer));});
