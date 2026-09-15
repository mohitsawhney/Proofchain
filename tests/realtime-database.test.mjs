import { after, before, test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { ref, set, get, update, remove, serverTimestamp } from 'firebase/database';
import { generateDeviceKey, publicOnly, sha256, makeEvent } from '../lib/crypto/core.ts';

let env;

before(async () => {
 env = await initializeTestEnvironment({
  projectId: 'demo-proofchain',
  database: {
   rules: await readFile(new URL('../database.rules.json', import.meta.url), 'utf8'),
   host: '127.0.0.1',
   port: 9000,
  },
 });
});

after(async () => {
 await env?.cleanup();
});

async function fixture() {
 const alice = await generateDeviceKey('alice');
 const bob = await generateDeviceKey('bob');
 const adb = env.authenticatedContext('alice').database();
 const bdb = env.authenticatedContext('bob').database();
 await env.withSecurityRulesDisabled(async (context) => {
  const db = context.database();
  await set(ref(db, 'users/alice'), { userId: 'alice' });
  await set(ref(db, 'users/bob'), { userId: 'bob' });
 });
 await set(ref(adb, `deviceKeys/${alice.keyId}`), publicOnly(alice));
 await set(ref(bdb, `deviceKeys/${bob.keyId}`), publicOnly(bob));
 const record = {
  id: `EV-${crypto.randomUUID()}`,
  title: 'Test record',
  description: '',
  sha256: await sha256('file'),
  fileSize: 4,
  mimeType: 'text/plain',
  ownerId: 'alice',
  registeredAt: new Date().toISOString(),
  perceptualHash: null,
  c2paStatus: 'Not analysed',
  scope: 'firebase',
 };
 const event = await makeEvent(record, alice, [], 'REGISTER', null, record.sha256);
 const root = {
  record,
  headHash: event.eventHash,
  eventCount: 1,
  currentCustodian: 'alice',
  pendingRecipient: null,
  participants: { alice: true },
  lastEventId: event.eventId,
  updatedAt: serverTimestamp(),
  events: { [event.eventId]: event },
 };
 return { alice, bob, adb, bdb, record, event, root };
}

async function commit(db, root) {
 return set(ref(db, `evidence/${root.record.id}`), root);
}

async function registered() {
 const fixtureData = await fixture();
 await assertSucceeds(commit(fixtureData.adb, fixtureData.root));
 return fixtureData;
}

async function transferred() {
 const fixtureData = await registered();
 const transfer = await makeEvent(fixtureData.record, fixtureData.alice, [fixtureData.event], 'TRANSFER', 'bob');
 const transferRoot = {
  ...fixtureData.root,
  headHash: transfer.eventHash,
  eventCount: 2,
  pendingRecipient: 'bob',
  participants: { alice: true, bob: true },
  lastEventId: transfer.eventId,
  updatedAt: serverTimestamp(),
  events: { [fixtureData.event.eventId]: fixtureData.event, [transfer.eventId]: transfer },
 };
 await assertSucceeds(commit(fixtureData.adb, transferRoot));
 return { ...fixtureData, transfer, transferRoot };
}

test('Authenticated registration succeeds', async () => {
 await registered();
});

test('Unauthenticated registration is denied', async () => {
 const fixtureData = await fixture();
 await assertFails(commit(env.unauthenticatedContext().database(), fixtureData.root));
});

test('Nonparticipant cannot read evidence', async () => {
 const fixtureData = await registered();
 await assertFails(get(ref(env.authenticatedContext('mallory').database(), `evidence/${fixtureData.record.id}`)));
});

test('Owner cannot overwrite a historical event', async () => {
 const fixtureData = await registered();
 await assertFails(update(ref(fixtureData.adb, `evidence/${fixtureData.record.id}/events/${fixtureData.event.eventId}`), { timestamp: 'changed' }));
});

test('Owner cannot delete historical events or evidence', async () => {
 const fixtureData = await registered();
 await assertFails(remove(ref(fixtureData.adb, `evidence/${fixtureData.record.id}/events/${fixtureData.event.eventId}`)));
 await assertFails(remove(ref(fixtureData.adb, `evidence/${fixtureData.record.id}`)));
});

test('Public key overwrite and deletion are denied', async () => {
 const fixtureData = await fixture();
 await assertFails(set(ref(fixtureData.adb, `deviceKeys/${fixtureData.alice.keyId}`), publicOnly(fixtureData.alice)));
 await assertFails(remove(ref(fixtureData.adb, `deviceKeys/${fixtureData.alice.keyId}`)));
});

test('Forging another user key ownership is denied', async () => {
 const fixtureData = await fixture();
 const forged = await generateDeviceKey('bob');
 await assertFails(set(ref(fixtureData.adb, `deviceKeys/${forged.keyId}`), publicOnly(forged)));
});

test('A head update without a matching event is denied', async () => {
 const fixtureData = await registered();
 await assertFails(update(ref(fixtureData.adb, `evidence/${fixtureData.record.id}`), { headHash: 'a'.repeat(64), eventCount: 2, updatedAt: serverTimestamp() }));
});

test('A detached event without a head update is denied', async () => {
 const fixtureData = await registered();
 const event = await makeEvent(fixtureData.record, fixtureData.alice, [fixtureData.event], 'VERIFY', null, fixtureData.record.sha256);
 await assertFails(set(ref(fixtureData.adb, `evidence/${fixtureData.record.id}/events/${event.eventId}`), event));
});

test('Changing immutable record data is denied', async () => {
 const fixtureData = await registered();
 await assertFails(update(ref(fixtureData.adb, `evidence/${fixtureData.record.id}`), { 'record/title': 'edited', updatedAt: serverTimestamp() }));
});

test('Transfer and exact recipient acceptance succeed', async () => {
 const fixtureData = await transferred();
 const receive = await makeEvent(fixtureData.record, fixtureData.bob, [fixtureData.event, fixtureData.transfer], 'RECEIVE', null, fixtureData.record.sha256);
 const receiveRoot = {
  ...fixtureData.transferRoot,
  headHash: receive.eventHash,
  eventCount: 3,
  currentCustodian: 'bob',
  pendingRecipient: null,
  lastEventId: receive.eventId,
  updatedAt: serverTimestamp(),
  events: { ...fixtureData.transferRoot.events, [receive.eventId]: receive },
 };
 await assertSucceeds(commit(fixtureData.bdb, receiveRoot));
});

test('A signed wrong-digest receipt is denied by rules', async () => {
 const fixtureData = await transferred();
 const receive = await makeEvent(fixtureData.record, fixtureData.bob, [fixtureData.event, fixtureData.transfer], 'RECEIVE', null, await sha256('wrong'));
 const receiveRoot = { ...fixtureData.transferRoot, headHash: receive.eventHash, eventCount: 3, currentCustodian: 'bob', pendingRecipient: null, lastEventId: receive.eventId, updatedAt: serverTimestamp(), events: { ...fixtureData.transferRoot.events, [receive.eventId]: receive } };
 await assertFails(commit(fixtureData.bdb, receiveRoot));
});

test('Sender cannot accept on behalf of recipient', async () => {
 const fixtureData = await transferred();
 const receive = await makeEvent(fixtureData.record, fixtureData.alice, [fixtureData.event, fixtureData.transfer], 'RECEIVE', null, fixtureData.record.sha256);
 const receiveRoot = { ...fixtureData.transferRoot, headHash: receive.eventHash, eventCount: 3, currentCustodian: 'bob', pendingRecipient: null, lastEventId: receive.eventId, updatedAt: serverTimestamp(), events: { ...fixtureData.transferRoot.events, [receive.eventId]: receive } };
 await assertFails(commit(fixtureData.adb, receiveRoot));
});

test('Recipient cannot silently replace pending destination', async () => {
 const fixtureData = await transferred();
 await assertFails(update(ref(fixtureData.bdb, `evidence/${fixtureData.record.id}`), { pendingRecipient: 'mallory', updatedAt: serverTimestamp() }));
});

test('Fork from a stale chain head is denied', async () => {
 const fixtureData = await transferred();
 const fork = await makeEvent(fixtureData.record, fixtureData.alice, [fixtureData.event], 'VERIFY', null, fixtureData.record.sha256);
 const forkRoot = { ...fixtureData.transferRoot, headHash: fork.eventHash, lastEventId: fork.eventId, updatedAt: serverTimestamp(), events: { ...fixtureData.transferRoot.events, [fork.eventId]: fork } };
 await assertFails(commit(fixtureData.adb, forkRoot));
});

test('A participant can create their own index after a record is saved', async () => {
 const fixtureData = await registered();
 await assertSucceeds(set(ref(fixtureData.adb, `userRecords/alice/${fixtureData.record.id}`), true));
 await assertFails(set(ref(fixtureData.adb, `userRecords/mallory/${fixtureData.record.id}`), true));
});
