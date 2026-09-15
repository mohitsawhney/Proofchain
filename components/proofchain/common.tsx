'use client';
import {useRef,useState,useEffect} from 'react';
import {FileUp,LockKeyhole,Check,Copy,File,LoaderCircle,X,ShieldCheck,ArrowUpRight} from 'lucide-react';
import {Button} from '@/components/ui/button';
import {hashFile} from '@/lib/evidence/hashing';
import {inspectMetadata,inspectCredentials} from '@/lib/evidence/analysis';
import {friendlyError} from '@/lib/firebase/client';
import type {FileAnalysis} from '@/types/proofchain';
export const short=(v:string,n=12)=>v.length>n*2?v.slice(0,n)+'…'+v.slice(-6):v;
export const bytes=(n:number)=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(2)+' MB':(n/1073741824).toFixed(2)+' GB';
export const date=(v:string)=>new Date(v).toLocaleString(undefined,{month:'short',day:'numeric',year:'numeric',hour:'2-digit',minute:'2-digit'});
export function CopyValue({value,compact=false}:{value:string;compact?:boolean}){const [copied,setCopied]=useState(false),[error,setError]=useState(false);return <div className="copy-value"><code title={value}>{compact?short(value):value}</code><Button variant="ghost" size="icon-sm" aria-label="Copy value" onClick={async()=>{try{await navigator.clipboard.writeText(value);setCopied(true);setTimeout(()=>setCopied(false),1800);}catch{setError(true);}}}>{copied?<Check size={15}/>:<Copy size={15}/>}</Button>{error&&<small>Select and copy the text.</small>}</div>;}
export function Badge({children,tone='neutral'}:{children:React.ReactNode;tone?:'green'|'amber'|'red'|'neutral'}){return <span className={'status-badge '+tone}>{children}</span>;}
export function PageTitle({eyebrow,title,description,actions}:{eyebrow:string;title:string;description?:string;actions?:React.ReactNode}){return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{description&&<p className="subheading">{description}</p>}</div>{actions&&<div className="actions">{actions}</div>}</div>;}
export function Notice({children,error=false}:{children:React.ReactNode;error?:boolean}){return <div role={error?'alert':'status'} className={'notice '+(error?'error':'')}><LockKeyhole size={17}/><div>{children}</div></div>;}
export function FileDropzone({onAnalysis,label='Choose your evidence file',initialFile}:{onAnalysis:(a:FileAnalysis|null)=>void;label?:string;initialFile?:File|null}){
 const input=useRef<HTMLInputElement>(null),controller=useRef<AbortController|null>(null),version=useRef(0);
 const [busy,setBusy]=useState(false),[progress,setProgress]=useState(0),[error,setError]=useState(''),[analysis,setAnalysis]=useState<FileAnalysis|null>(null),[selected,setSelected]=useState<File|null>(null),[drag,setDrag]=useState(false),[c2paBusy,setC2paBusy]=useState(false);
 const runRef=useRef<(file:File)=>void>(()=>{});
 async function select(file:File){
  controller.current?.abort();const signal=new AbortController();controller.current=signal;const current=++version.current;setBusy(true);setProgress(0);setError('');setAnalysis(null);setSelected(file);onAnalysis(null);
  try{const digest=await hashFile(file,setProgress,signal.signal);const a:FileAnalysis={sha256:digest,size:file.size,name:file.name,mimeType:file.type||'application/octet-stream',metadata:{},metadataMessage:'Reported metadata has not been inspected.',perceptualHash:null,c2pa:{status:'Not analysed',detail:'Optional local inspection of embedded Content Credentials.'}};
   if(current!==version.current)return;setAnalysis(a);onAnalysis(a);
   const details=await inspectMetadata(file);if(current!==version.current)return;const enriched={...a,...details};setAnalysis(enriched);onAnalysis(enriched);
  }catch(err){if(current===version.current)setError(friendlyError(err));}finally{if(current===version.current)setBusy(false);}
 }
 useEffect(()=>{runRef.current=select;});
 useEffect(()=>{if(initialFile)runRef.current(initialFile);},[initialFile]);
 useEffect(()=>()=>{controller.current?.abort();version.current++;},[]);
 return <div className="file-selector"><input ref={input} aria-label={label} type="file" className="sr-only" onChange={e=>{if(e.target.files?.[0])void select(e.target.files[0]);e.target.value='';}}/>
 <button type="button" className={'dropzone '+(drag?'dragging':'')} disabled={busy} onClick={()=>input.current?.click()} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);if(!busy&&e.dataTransfer.files[0])void select(e.dataTransfer.files[0]);}}>
 <span className="drop-icon">{busy?<LoaderCircle className="spin"/>:analysis?<File/>:<FileUp/>}</span><strong>{busy?'Hashing locally…':analysis?analysis.name:label}</strong><span>{busy?progress+'% of file processed':analysis?bytes(analysis.size)+' · Click to choose another file':'Drop a file here, or browse your device'}</span><small><LockKeyhole size={13}/> Your evidence stays on your device</small></button>
 {busy&&<div className="hash-progress"><progress max={100} value={progress} aria-label="Hashing progress"/><Button variant="ghost" size="sm" onClick={()=>{version.current++;controller.current?.abort();setBusy(false);setAnalysis(null);onAnalysis(null);setError('Hashing cancelled.');}}><X/>Cancel</Button></div>}
 {error&&<Notice error>{error}</Notice>}
 {analysis&&<div className="analysis"><div className="section-label"><span><ShieldCheck size={16}/> FILE ANALYSIS</span><Badge>Processed locally</Badge></div><label>SHA-256 fingerprint</label><CopyValue value={analysis.sha256}/><div className="split-data"><div><label>File type</label><p>{analysis.mimeType}</p></div><div><label>File size</label><p>{bytes(analysis.size)}</p></div></div><details><summary>Reported metadata <ArrowUpRight size={14}/></summary><p className="muted">{analysis.metadataMessage} GPS is excluded. These fields are not saved.</p>{Object.entries(analysis.metadata).map(([k,v])=><div className="data-line" key={k}><span>{k}</span><span>{v}</span></div>)}</details><div className="c2pa-row"><div><strong>Content Credentials</strong><p>{analysis.c2pa.status}</p></div><Button size="sm" variant="outline" disabled={c2paBusy||busy} onClick={async()=>{if(!selected)return;const id=version.current;setC2paBusy(true);try{const c2pa=await inspectCredentials(selected);if(id===version.current){const next={...analysis,c2pa};setAnalysis(next);onAnalysis(next);}}finally{setC2paBusy(false);}}}>{c2paBusy?'Inspecting…':'Inspect locally'}</Button></div><p className="fine-print">{analysis.c2pa.detail}</p></div>}
 </div>;
}
