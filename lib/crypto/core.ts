import canonicalize from 'canonicalize';
import { z } from 'zod';
import type { Evidence, EventPayload, CustodyEvent, DeviceKey, PublicDeviceKey, ProofBundle, ChainResult, Check } from '@/types/proofchain';

const encoder = new TextEncoder();
export const hex = (buffer: ArrayBuffer) => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
export async function sha256(value: string | ArrayBuffer): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? encoder.encode(value) : value));
}
export function canonical(value: unknown): string {
  const result = canonicalize(value);
  if (typeof result !== 'string') throw new Error('The signed value must be valid JSON.');
  return result;
}
export async function keyFingerprint(publicKey: JsonWebKey): Promise<string> {
  if (publicKey.kty !== 'EC' || publicKey.crv !== 'P-256' || !publicKey.x || !publicKey.y || publicKey.d) throw new Error('Invalid P-256 public key.');
  return 'KEY-' + await sha256(canonical({crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x, y: publicKey.y}));
}
export async function generateDeviceKey(userId: string): Promise<DeviceKey> {
  if (!crypto.subtle || !crypto.randomUUID) throw new Error('Secure connection required. Open ProofChain over HTTPS to use digital signatures.');
  // Web Crypto keeps the private key non-extractable; public keys remain exportable.
  const pair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign', 'verify']);
  const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {userId, keyId: await keyFingerprint(publicKey), publicKey, privateKey: pair.privateKey, algorithm: 'ECDSA-P256-SHA256'};
}
export function publicOnly(key: DeviceKey): PublicDeviceKey {
  return {keyId: key.keyId, userId: key.userId, publicKey: key.publicKey, algorithm: key.algorithm};
}
export async function signEvent(payload: EventPayload, key: DeviceKey): Promise<CustodyEvent> {
  if (payload.actorKeyId !== key.keyId || payload.actorUserId !== key.userId) throw new Error('Signing identity mismatch.');
  const bytes = encoder.encode(canonical(payload));
  const signature = await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, key.privateKey, bytes);
  return {...payload, eventHash: await sha256(canonical(payload)), signature: btoa(String.fromCharCode(...new Uint8Array(signature)))};
}
export function eventPayload(event: CustodyEvent): EventPayload {
  const {eventHash: _hash, signature: _signature, ...payload} = event;
  void _hash; void _signature;
  return payload;
}
export async function verifyEventSignature(event: CustodyEvent, key?: PublicDeviceKey): Promise<boolean> {
  try {
    if (!key || key.keyId !== event.actorKeyId || key.userId !== event.actorUserId || await keyFingerprint(key.publicKey) !== key.keyId) return false;
    const pub = await crypto.subtle.importKey('jwk', key.publicKey, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['verify']);
    const sig = Uint8Array.from(atob(event.signature), c => c.charCodeAt(0));
    return await crypto.subtle.verify({name: 'ECDSA', hash: 'SHA-256'}, pub, sig, encoder.encode(canonical(eventPayload(event))));
  } catch { return false; }
}
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const identifier = z.string().min(1).max(160).regex(/^[A-Za-z0-9_-]+$/);
const keySchema = z.object({keyId: z.string().regex(/^KEY-[a-f0-9]{64}$/), userId: identifier, algorithm: z.literal('ECDSA-P256-SHA256'), publicKey: z.object({kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string(), y: z.string(), ext: z.boolean().optional(), key_ops: z.array(z.string()).optional()}).strict()}).strict();
export const evidenceSchema = z.object({id: identifier, title: z.string().min(1).max(160), description: z.string().max(2000), sha256: digest, fileSize: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), mimeType: z.string().max(200), ownerId: identifier, registeredAt: z.string().datetime(), perceptualHash: z.string().regex(/^[a-f0-9]{16}$/).nullable(), c2paStatus: z.string().max(100), scope: z.enum(['local', 'firebase'])}).strict();
const eventSchema = z.object({version: z.literal(1), eventId: identifier, evidenceId: identifier, sequence: z.number().int().nonnegative(), eventType: z.enum(['REGISTER', 'TRANSFER', 'RECEIVE', 'VERIFY', 'REJECT_TRANSFER']), actorUserId: identifier, actorKeyId: z.string(), evidenceSha256: digest, evidenceRecordHash: digest, previousEventHash: z.union([digest, z.literal('GENESIS')]), timestamp: z.string().datetime(), toUserId: identifier.nullable(), verifiedSha256: digest.nullable(), eventHash: digest, signature: z.string().min(1).max(200)}).strict();
const bundleSchema = z.object({proofChainVersion: z.literal('1.0'), evidence: evidenceSchema, custodyEvents: z.array(eventSchema).min(1).max(5000), publicKeys: z.array(keySchema).min(1).max(1000), checkpoint: z.object({eventCount: z.number().int().min(1), headHash: digest}).strict(), timestampProofs: z.tuple([]), exportedAt: z.string().datetime()}).strict();
export function parseBundle(value: unknown): ProofBundle {
  const result = bundleSchema.safeParse(value);
  if (!result.success) throw new Error('Invalid proof bundle: ' + result.error.issues[0].path.join('.') + ' — ' + result.error.issues[0].message);
  return result.data;
}
export async function verifyFullCustodyChain(input: ProofBundle): Promise<ChainResult> {
  const checks: Check[] = [];
  const add = (valid: boolean, eventId: string, check: string, reason: string) => checks.push({valid, eventId, check, reason});
  let bundle: ProofBundle;
  try { bundle = parseBundle(input); } catch (err) {
    return {valid:false, checks:[{valid:false,eventId:'bundle',check:'SCHEMA',reason: String(err)}],currentCustodian:'',pendingRecipient:null,hashChainValid:false,signaturesValid:false};
  }
  const recordHash = await sha256(canonical(bundle.evidence));
  let previous = 'GENESIS', custodian = bundle.evidence.ownerId, pending: string | null = null;
  const seen = new Set<string>();
  add(new Set(bundle.publicKeys.map(k => k.keyId)).size === bundle.publicKeys.length, 'bundle', 'KEYS', 'Public key identifiers must be unique.');
  for (let index = 0; index < bundle.custodyEvents.length; index++) {
    const event = bundle.custodyEvents[index], id = event.eventId;
    add(!seen.has(id), id, 'SEQUENCE', 'Event identifiers must not repeat.'); seen.add(id);
    add(event.sequence === index && event.previousEventHash === previous, id, 'LINK', 'Sequence and previous event hash must match the preceding event.');
    add(event.eventHash === await sha256(canonical(eventPayload(event))), id, 'HASH', 'Event hash must match its canonical payload.');
    add(event.evidenceId === bundle.evidence.id && event.evidenceSha256 === bundle.evidence.sha256 && event.evidenceRecordHash === recordHash, id, 'BINDING', 'Every event must bind the same evidence record and digest.');
    add(await verifyEventSignature(event, bundle.publicKeys.find(k => k.keyId === event.actorKeyId)), id, 'SIGNATURE', 'ECDSA signature must verify against the actor’s fingerprinted public key.');
    let legal = false;
    if (index === 0) legal = event.eventType === 'REGISTER' && event.actorUserId === custodian && event.toUserId === null && event.verifiedSha256 === bundle.evidence.sha256 && event.timestamp === bundle.evidence.registeredAt;
    else if (event.eventType === 'TRANSFER') {
      legal = event.actorUserId === custodian && !pending && !!event.toUserId && event.toUserId !== custodian && event.verifiedSha256 === null;
      if (legal) pending = event.toUserId;
    } else if (event.eventType === 'RECEIVE') {
      legal = !!pending && event.actorUserId === pending && event.verifiedSha256 === bundle.evidence.sha256 && event.toUserId === null;
      if (legal) { custodian = pending!; pending = null; }
    } else if (event.eventType === 'REJECT_TRANSFER') {
      legal = !!pending && event.actorUserId === pending && event.toUserId === null && event.verifiedSha256 === null;
      if (legal) pending = null;
    } else if (event.eventType === 'VERIFY') legal = [custodian, pending].includes(event.actorUserId) && event.verifiedSha256 === bundle.evidence.sha256 && event.toUserId === null;
    add(legal, id, 'CUSTODY', 'Actor, event order, recipient and received digest must satisfy the custody state machine.');
    previous = event.eventHash;
  }
  add(bundle.checkpoint.eventCount === bundle.custodyEvents.length && bundle.checkpoint.headHash === previous, 'checkpoint', 'CHECKPOINT', 'Event count and head must match the exported checkpoint.');
  return {valid: checks.every(c => c.valid), checks, currentCustodian: custodian, pendingRecipient: pending, hashChainValid: checks.filter(c => ['LINK','HASH','BINDING','CHECKPOINT','SEQUENCE'].includes(c.check)).every(c => c.valid), signaturesValid: checks.filter(c => c.check === 'SIGNATURE' || c.check === 'KEYS').every(c => c.valid)};
}
export async function makeEvent(evidence: Evidence, key: DeviceKey, prior: CustodyEvent[], eventType: EventPayload['eventType'], toUserId: string | null = null, verifiedSha256: string | null = null): Promise<CustodyEvent> {
  return signEvent({version:1,eventId:crypto.randomUUID(),evidenceId:evidence.id,sequence:prior.length,eventType,actorUserId:key.userId,actorKeyId:key.keyId,evidenceSha256:evidence.sha256,evidenceRecordHash:await sha256(canonical(evidence)),previousEventHash:prior.at(-1)?.eventHash ?? 'GENESIS',timestamp:prior.length ? new Date().toISOString() : evidence.registeredAt,toUserId,verifiedSha256}, key);
}
export function pack(evidence: Evidence, custodyEvents: CustodyEvent[], publicKeys: PublicDeviceKey[]): ProofBundle {
  return {proofChainVersion:'1.0',evidence,custodyEvents,publicKeys,checkpoint:{eventCount:custodyEvents.length,headHash:custodyEvents.at(-1)!.eventHash},timestampProofs:[],exportedAt:new Date().toISOString()};
}
