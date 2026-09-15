import {
 get,
 ref,
 runTransaction,
 serverTimestamp,
 update,
 type DatabaseReference,
} from 'firebase/database';
import { firebase, withTimeout } from './client';
import { parseBundle, verifyFullCustodyChain } from '@/lib/crypto/core';
import type { ProofBundle, PublicDeviceKey, CustodyEvent, Evidence } from '@/types/proofchain';

/**
 * A proof and its append-only event stream live together at one RTDB node.
 * Keeping the head and events in the same transaction lets the database rules
 * reject detached events and stale forks without a server-side trusted writer.
 */
interface CloudRecord {
 record: Evidence;
 headHash: string;
 eventCount: number;
 currentCustodian: string;
 pendingRecipient: string | null;
 participants: Record<string, true>;
 lastEventId: string;
 updatedAt: number;
 events: Record<string, CustodyEvent>;
}

type CloudRecordWrite = Omit<CloudRecord, 'updatedAt'> & { updatedAt: ReturnType<typeof serverTimestamp> };

function path(...parts: string[]): string {
 return parts.map((part) => encodeURIComponent(part)).join('/');
}

// Realtime Database treats null as deletion, so nullable signed fields disappear
// from snapshots. Restore them before schema/hash/signature verification.
function normalizeEvidence(record: Evidence): Evidence {
 return { ...record, perceptualHash: record.perceptualHash ?? null };
}

function normalizeEvent(event: CustodyEvent): CustodyEvent {
 return {
  ...event,
  toUserId: event.toUserId ?? null,
  verifiedSha256: event.verifiedSha256 ?? null,
 };
}

function asRecord(value: unknown): CloudRecord {
 if (!value || typeof value !== 'object') throw new Error('The Firebase record is malformed.');
 const record = value as Partial<CloudRecord>;
 if (!record.record || !record.events || typeof record.events !== 'object') throw new Error('The Firebase record is incomplete.');
 const events = Object.fromEntries(
  Object.entries(record.events as Record<string, CustodyEvent>).map(([id, event]) => [id, normalizeEvent(event)]),
 );
 return {
  ...record,
  record: normalizeEvidence(record.record),
  pendingRecipient: record.pendingRecipient ?? null,
  participants: record.participants ?? {},
  events,
 } as CloudRecord;
}

function participantsFor(bundle: ProofBundle, checked: Awaited<ReturnType<typeof verifyFullCustodyChain>>, previous?: CloudRecord): Record<string, true> {
 const participants: Record<string, true> = { ...(previous?.participants ?? {}) };
 for (const uid of [bundle.evidence.ownerId, checked.currentCustodian, checked.pendingRecipient, bundle.custodyEvents.at(-1)?.toUserId]) {
  if (uid) participants[uid] = true;
 }
 return participants;
}

function latestEvent(bundle: ProofBundle): CustodyEvent {
 const event = bundle.custodyEvents.at(-1);
 if (!event) throw new Error('A custody chain must contain at least one event.');
 return event;
}

function writeForBundle(bundle: ProofBundle, checked: Awaited<ReturnType<typeof verifyFullCustodyChain>>): CloudRecordWrite {
 const event = latestEvent(bundle);
 const events = Object.fromEntries(bundle.custodyEvents.map((item) => [item.eventId, item]));
 return {
  record: bundle.evidence,
  headHash: event.eventHash,
  eventCount: bundle.custodyEvents.length,
  currentCustodian: checked.currentCustodian,
  pendingRecipient: checked.pendingRecipient,
  participants: participantsFor(bundle, checked),
  lastEventId: event.eventId,
  updatedAt: serverTimestamp(),
  events,
 };
}

async function ensureUser(userId: string): Promise<void> {
 const userRef = ref(firebase().db, path('users', userId));
 await withTimeout(runTransaction(userRef, (current) => current ?? { userId }));
}

export async function registerPublicKey(key: PublicDeviceKey): Promise<void> {
 const db = firebase().db;
 await ensureUser(key.userId);
 const keyRef = ref(db, path('deviceKeys', key.keyId));
 await withTimeout(runTransaction(keyRef, (current) => {
  if (current == null) return key;
  if (current.userId !== key.userId) throw new Error('Public key ownership mismatch.');
  return current;
 }));
}

export async function listCloudEvidence(uid: string): Promise<Evidence[]> {
 const db = firebase().db;
 const index = await withTimeout(get(ref(db, path('userRecords', uid))));
 const ids = Object.keys((index.val() as Record<string, true> | null) ?? {}).slice(0, 100);
 const records = await Promise.all(ids.map(async (id) => {
  try {
   const snapshot = await withTimeout(get(ref(db, path('evidence', id))));
   return snapshot.exists() ? asRecord(snapshot.val()).record : null;
  } catch {
   return null;
  }
 }));
 return records.filter((record): record is Evidence => record !== null);
}

export async function getCloudProof(id: string): Promise<ProofBundle> {
 const db = firebase().db;
 const snapshot = await withTimeout(get(ref(db, path('evidence', id))));
 if (!snapshot.exists()) throw new Error('Evidence not found or unavailable to this account.');
 const data = asRecord(snapshot.val());
 const custodyEvents = Object.values(data.events).sort((a, b) => a.sequence - b.sequence);
 const ids = [...new Set(custodyEvents.map((event) => event.actorKeyId))];
 const publicKeys = await Promise.all(ids.map(async (keyId) => {
  const key = await withTimeout(get(ref(db, path('deviceKeys', keyId))));
  if (!key.exists()) throw new Error('A signing key is missing.');
  return key.val() as PublicDeviceKey;
 }));
 return parseBundle({
  proofChainVersion: '1.0',
  evidence: data.record,
  custodyEvents,
  publicKeys,
  checkpoint: { eventCount: data.eventCount, headHash: data.headHash },
  timestampProofs: [],
  exportedAt: new Date().toISOString(),
 });
}

function recordRef(id: string): DatabaseReference {
 return ref(firebase().db, path('evidence', id));
}

export async function saveCloudProof(bundle: ProofBundle, expectedHead?: string): Promise<void> {
 const db = firebase().db;
 const event = latestEvent(bundle);
 const checked = await verifyFullCustodyChain(bundle);
 if (!checked.valid) throw new Error('Cannot store an invalid custody chain.');
 const target = recordRef(bundle.evidence.id);
 const result = await withTimeout(runTransaction(target, (currentValue) => {
  if (currentValue == null) {
   if (expectedHead || bundle.custodyEvents.length !== 1) throw new Error('The custody record changed. Reload it before continuing.');
   return writeForBundle(bundle, checked);
  }
  const previous = asRecord(currentValue);
  if (!expectedHead || previous.headHash !== expectedHead) throw new Error('The custody record changed. Reload it before continuing.');
  if (bundle.custodyEvents.length !== previous.eventCount + 1 || event.previousEventHash !== previous.headHash) {
   throw new Error('The custody record changed. Reload it before continuing.');
  }
  const existing = previous.events[event.eventId];
  if (existing) {
   if (JSON.stringify(existing) !== JSON.stringify(event)) throw new Error('This event ID is already used by another event.');
   return previous;
  }
  return {
   ...previous,
   headHash: event.eventHash,
   eventCount: bundle.custodyEvents.length,
   currentCustodian: checked.currentCustodian,
   pendingRecipient: checked.pendingRecipient,
   participants: participantsFor(bundle, checked, previous),
   lastEventId: event.eventId,
   updatedAt: serverTimestamp(),
   events: { ...previous.events, [event.eventId]: event },
  } satisfies CloudRecordWrite;
 }));
 if (!result.committed) throw new Error('The custody write was cancelled.');

 const saved = asRecord(result.snapshot.val());
 const indexes: Record<string, true> = {};
 for (const uid of Object.keys(saved.participants)) indexes[path('userRecords', uid, bundle.evidence.id)] = true;
 await withTimeout(update(ref(db), indexes));
}
