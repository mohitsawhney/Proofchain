# Deploy ProofChain on GitHub Pages

This copy has been adapted for GitHub Pages static hosting. Firebase Authentication and Realtime Database remain the backend.

## 1. Create the repository

Create a GitHub repository, preferably named `proofchain`, and upload/push all files in this folder to the `main` branch.

## 2. Enable GitHub Pages

In the repository, open **Settings → Pages → Build and deployment → Source** and choose **GitHub Actions**.

The included workflow `.github/workflows/deploy-pages.yml` builds the Next.js static export and deploys the `out` directory.

## 3. Authorize the GitHub domain in Firebase

In Firebase Console → Authentication → Settings → Authorized domains, add:

`YOUR_GITHUB_USERNAME.github.io`

For this account that will normally be `mohitsawhney.github.io`. The repository path (for example `/proofchain`) is not part of the authorized domain.

Also ensure Google sign-in is enabled under Authentication → Sign-in method.

## 4. Deploy database rules

The website deployment does not deploy Realtime Database rules. From a Firebase-authenticated machine run:

```bash
pnpm exec firebase login
pnpm exec firebase deploy --only database --project blockchainverify-33742
```

## 5. Expected URL

For a repository named `proofchain`, the Pages URL will normally be:

`https://YOUR_GITHUB_USERNAME.github.io/proofchain/`

The workflow automatically sets the correct Next.js `basePath` from the repository name.

## Notes

- GitHub Pages is static hosting; this version converts the evidence detail route to `/evidence/?id=...` so arbitrary evidence IDs work without server-side routing.
- Google sign-in primarily uses a popup. Firebase's redirect fallback can be more fragile on non-Firebase hosting in browsers that block third-party storage.
- Firebase web configuration values are public client configuration. Do not add service-account keys or Admin SDK secrets to the repository.
