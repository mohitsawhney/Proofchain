import type { DeviceKey, ProofBundle } from '@/types/proofchain';
import { generateDeviceKey } from '@/lib/crypto/core';
let opening: Promise<IDBDatabase> | undefined;
function database(): Promise<IDBDatabase> {
  if (!opening) opening = new Promise((resolve, reject) => {
    const request = indexedDB.open('proofchain-v1',1);
    request.onupgradeneeded = () => { request.result.createObjectStore('keys'); request.result.createObjectStore('proofs'); request.result.createObjectStore('preferences'); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => { opening = undefined; reject(new Error('Local secure storage is unavailable. Enable browser storage to continue.')); };
  });
  return opening;
}
export async function localRead<T>(store: string, key: string): Promise<T | undefined> {
  const db = await database();
  return new Promise((resolve,reject) => { const r = db.transaction(store).objectStore(store).get(key); r.onsuccess = () => resolve(r.result as T | undefined); r.onerror = () => reject(r.error); });
}
export async function localWrite<T>(store: string, key: string, value: T): Promise<void> {
  const db = await database();
  return new Promise((resolve,reject) => { const t = db.transaction(store,'readwrite'); t.objectStore(store).put(value,key); t.oncomplete = () => resolve(); t.onerror = () => reject(t.error); t.onabort = () => reject(t.error ?? new Error('Storage transaction aborted.')); });
}
async function getOrInsert<T>(storeName:string,key:string,candidate:T):Promise<T> {
  const db=await database();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(storeName,'readwrite'),store=tx.objectStore(storeName),read=store.get(key);
    let selected:T=candidate;
    read.onsuccess=()=>{if(read.result!==undefined)selected=read.result as T;else store.add(candidate,key);};
    tx.oncomplete=()=>resolve(selected);tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error ?? new Error('Identity storage was interrupted.'));
  });
}
const pendingKeys = new Map<string,Promise<DeviceKey>>();
export function deviceKey(userId: string): Promise<DeviceKey> {
  let promise = pendingKeys.get(userId);
  if (!promise) {
    promise = (async () => {
      const existing = await localRead<DeviceKey>('keys',userId); if (existing) return existing;
      const created = await generateDeviceKey(userId); return getOrInsert('keys',userId,created);
    })();
    pendingKeys.set(userId,promise); promise.catch(() => pendingKeys.delete(userId));
  }
  return promise;
}
export async function localIdentity(): Promise<string> {
  if (!crypto.subtle || !crypto.randomUUID) throw new Error('Secure connection required. Open ProofChain over HTTPS to create a signing key. Local file hashing remains available.');
  let id = await localRead<string>('preferences','identity');
  if (!id) id = await getOrInsert('preferences','identity','LOCAL-' + crypto.randomUUID());
  return id;
}
export async function listLocalProofs(): Promise<ProofBundle[]> {
  const db = await database();
  return new Promise((resolve,reject) => { const r=db.transaction('proofs').objectStore('proofs').getAll(); r.onsuccess=()=>resolve(r.result as ProofBundle[]); r.onerror=()=>reject(r.error); });
}
export async function appendLocalProof(bundle: ProofBundle, expectedHead?: string): Promise<void> {
  const db=await database();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction('proofs','readwrite'), store=tx.objectStore('proofs'), get=store.get(bundle.evidence.id);
    let conflict=false;
    get.onsuccess=()=>{ const current=get.result as ProofBundle | undefined;
      if ((expectedHead && current?.checkpoint.headHash !== expectedHead) || (!expectedHead && current)) { conflict=true;tx.abort();return; }
      store.put(bundle,bundle.evidence.id);
    };
    tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(new Error(conflict?'This record changed in another tab. Refresh and try again.':'Local write failed.'));
  });
}
