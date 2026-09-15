import { initializeApp, getApp, getApps } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getDatabase } from 'firebase/database';
// Firebase browser configuration is public identification, never an Admin secret.
export const firebaseConfig = {
 apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY || 'AIzaSyCgPZhlM53MTQRU4-UynkYR0JildP0eTHo',
 authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN || 'blockchainverify-33742.firebaseapp.com',
 projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || 'blockchainverify-33742',
 appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID || '1:576731515499:web:a17aca35acd4ae5191bf2e',
 databaseURL: process.env.NEXT_PUBLIC_FIREBASE_DATABASE_URL || 'https://blockchainverify-33742-default-rtdb.firebaseio.com',
};
export function firebase() {
 const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
 return {auth:getAuth(app),db:getDatabase(app)};
}
export function friendlyError(error: unknown): string {
 const code = typeof error === 'object' && error && 'code' in error ? String(error.code) : '';
 if(code.includes('permission-denied')) return 'Firebase denied access. Confirm that your account is a participant and that the supplied Realtime Database rules are deployed.';
 if(/configuration-not-found|operation-not-allowed/.test(code)) return 'This sign-in method is not enabled in this Firebase project yet. Enable Google under Authentication → Sign-in method. You can still use the local demo and proof-bundle verification.';
 if(code.includes('popup-blocked')) return 'The browser blocked the Google sign-in window. Allow pop-ups for this site and try again.';
 if(code.includes('popup-closed-by-user') || code.includes('cancelled-popup-request')) return 'The Google sign-in window was closed before it finished.';
 if(code.includes('account-exists-with-different-credential')) return 'An account already exists with this email using a different sign-in method. Use that method first, then link Google from Firebase.';
 if(/invalid-api-key|api-key-not-valid/.test(code)) return 'The supplied Firebase configuration was rejected. Update the Firebase project settings; local verification remains available.';
 if(/invalid-credential|wrong-password|user-not-found/.test(code)) return 'The email or password was not accepted.';
 if(code.includes('email-already-in-use')) return 'An account already uses this email. Sign in instead.';
 if(code.includes('weak-password')) return 'Use a stronger password of at least 8 characters.';
 if(code.includes('network-request-failed') || code.includes('unavailable')) return 'Firebase could not be reached. Check your connection. Local analysis is still available.';
 if(code.includes('too-many-requests')) return 'Too many requests. Please try again later.';
 return error instanceof Error ? error.message : 'The operation could not be completed. Please retry.';
}
export async function withTimeout<T>(promise:Promise<T>,ms=15000):Promise<T>{
 let timer: ReturnType<typeof setTimeout> | undefined;
 try {return await Promise.race([promise,new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new Error('The server did not respond in time. Refresh before retrying a write; it may still complete.')),ms);})]);} finally {clearTimeout(timer);}
}
