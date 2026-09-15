import { createSHA256 } from 'hash-wasm';
self.onmessage = async (event: MessageEvent<{file: File}>) => {
  try {
    const file=event.data.file, hasher=await createSHA256(), chunk=4*1024*1024;
    hasher.init();
    for (let offset=0;offset<file.size;offset+=chunk) {
      hasher.update(new Uint8Array(await file.slice(offset,offset+chunk).arrayBuffer()));
      self.postMessage({progress:Math.min(100,Math.round((offset+chunk)/file.size*100))});
    }
    self.postMessage({digest:hasher.digest('hex'),progress:100});
  } catch { self.postMessage({error:'The file could not be read. Select it again and retry.'}); }
};
