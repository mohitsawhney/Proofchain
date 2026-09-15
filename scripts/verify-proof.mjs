#!/usr/bin/env node
// Node 22+ independent verifier; no Firebase, HTTP or browser dependency.
import {readFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {parseBundle,verifyFullCustodyChain} from '../lib/crypto/core.ts';
const [proofPath,filePath,expectedHead]=process.argv.slice(2);
if(!proofPath||!filePath){console.error('Usage: node --experimental-strip-types scripts/verify-proof.mjs bundle.json evidence-file [trusted-head-hash]');process.exit(2);}
try{
 const proof=parseBundle(JSON.parse(await readFile(proofPath,'utf8')));
 const hash=createHash('sha256');for await(const chunk of createReadStream(filePath))hash.update(chunk);const digest=hash.digest('hex');
 const chain=await verifyFullCustodyChain(proof);const exact=digest===proof.evidence.sha256;const checkpoint=expectedHead?expectedHead===proof.checkpoint.headHash:null;
 console.log(JSON.stringify({evidenceId:proof.evidence.id,exactFile:exact?'VERIFIED EXACT':'EXACT MATCH FAILED',sha256:digest,chainValid:chain.valid,signaturesValid:chain.signaturesValid,trustedCheckpointMatch:checkpoint,failures:chain.checks.filter(c=>!c.valid),limitations:'Self-contained proofs do not establish legal identity, trusted time or freshness. Compare known fingerprints and independently retained checkpoints.'},null,2));
 process.exitCode=exact&&chain.valid&&checkpoint!==false?0:1;
}catch(error){console.error(error.message);process.exitCode=2;}
