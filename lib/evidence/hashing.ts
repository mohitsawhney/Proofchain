import EvidenceWorker from '../../workers/evidence.worker?worker';
export function hashFile(file: File, onProgress: (p:number)=>void, signal: AbortSignal): Promise<string> {
  return new Promise((resolve,reject)=>{
    if(signal.aborted) return reject(new Error('Hashing cancelled.'));
    const worker=new EvidenceWorker();
    let settled=false;
    const finish=(error?:string,digest?:string)=>{ if(settled)return;settled=true;worker.terminate();signal.removeEventListener('abort',cancel);if(error)reject(new Error(error));else resolve(digest!); };
    const cancel=()=>finish('Hashing cancelled.');
    signal.addEventListener('abort',cancel,{once:true});
    worker.onmessage=(event:MessageEvent<{progress?:number;digest?:string;error?:string}>)=>{if(event.data.progress!==undefined)onProgress(event.data.progress);if(event.data.error)finish(event.data.error);if(event.data.digest)finish(undefined,event.data.digest);};
    worker.onerror=()=>finish('The hashing worker could not start. Refresh and try again.');
    worker.postMessage({file});
  });
}
