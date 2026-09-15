export type EventType = "REGISTER" | "TRANSFER" | "RECEIVE" | "VERIFY" | "REJECT_TRANSFER";
export interface Evidence {
 id: string; title: string; description: string; sha256: string; fileSize: number;
 mimeType: string; ownerId: string; registeredAt: string; perceptualHash: string | null;
 c2paStatus: string; scope: "local" | "firebase";
}
export interface EventPayload {
 version: 1; eventId: string; evidenceId: string; sequence: number; eventType: EventType;
 actorUserId: string; actorKeyId: string; evidenceSha256: string; evidenceRecordHash: string;
 previousEventHash: string; timestamp: string; toUserId: string | null; verifiedSha256: string | null;
}
export interface CustodyEvent extends EventPayload { eventHash: string; signature: string }
export interface PublicDeviceKey {
 keyId: string; userId: string; publicKey: JsonWebKey; algorithm: "ECDSA-P256-SHA256";
}
export interface DeviceKey extends PublicDeviceKey { privateKey: CryptoKey }
export interface ProofBundle {
 proofChainVersion: "1.0"; evidence: Evidence; custodyEvents: CustodyEvent[];
 publicKeys: PublicDeviceKey[]; checkpoint: { eventCount: number; headHash: string };
 timestampProofs: []; exportedAt: string;
}
export interface Check { valid: boolean; eventId: string; check: string; reason: string }
export interface ChainResult {
 valid: boolean; checks: Check[]; currentCustodian: string; pendingRecipient: string | null;
 hashChainValid: boolean; signaturesValid: boolean;
}
export interface FileAnalysis {
 sha256: string; size: number; mimeType: string; name: string;
 metadata: Record<string, string>; metadataMessage: string; perceptualHash: string | null;
 c2pa: { status: string; detail: string; issuer?: string };
}
