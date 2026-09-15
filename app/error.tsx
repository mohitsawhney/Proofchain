"use client";
export default function ErrorPage({reset}:{reset:()=>void}) { return <main style={{padding:48}}><h1>ProofChain could not load this view.</h1><p>Your local evidence files have not been uploaded.</p><button onClick={reset}>Try again</button></main>; }
