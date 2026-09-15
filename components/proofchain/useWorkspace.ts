'use client';
import {useCallback,useEffect,useState} from 'react';
import {onAuthStateChanged,signOut,type User} from 'firebase/auth';
import {firebase,friendlyError} from '@/lib/firebase/client';
import {deviceKey,localIdentity} from '@/lib/evidence/local-store';
import {registerPublicKey} from '@/lib/firebase/repository';
import {publicOnly} from '@/lib/crypto/core';
import {listEvidence} from '@/lib/evidence/service';
import type {DeviceKey,Evidence} from '@/types/proofchain';
export function useWorkspace(){
 const [user,setUser]=useState<User|null>(null),[uid,setUid]=useState(''),[key,setKey]=useState<DeviceKey|null>(null),[items,setItems]=useState<Evidence[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState('');
 useEffect(()=>{let active=true,generation=0;const unsub=onAuthStateChanged(firebase().auth,async current=>{
  const run=++generation;if(!active)return;setLoading(true);setUser(current);setItems([]);setKey(null);setError('');
  try{const identity=current?.uid ?? await localIdentity();const signing=await deviceKey(identity);if(!active||run!==generation)return;setUid(identity);setKey(signing);if(current)await registerPublicKey(publicOnly(signing));const evidence=await listEvidence(identity,!!current);if(active&&run===generation)setItems(evidence);}catch(err){if(active&&run===generation)setError(friendlyError(err));}finally{if(active&&run===generation)setLoading(false);}
 });return()=>{active=false;unsub();};},[]);
 const refresh=useCallback(async()=>{if(!uid)return;setError('');try{setItems(await listEvidence(uid,!!user));}catch(err){setError(friendlyError(err));}},[uid,user]);
 return {user,uid,key,items,loading,error,setError,refresh,cloud:!!user,signOut:()=>signOut(firebase().auth)};
}
export type Workspace=ReturnType<typeof useWorkspace>;
