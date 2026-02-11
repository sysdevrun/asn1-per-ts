# Publishing asn1-per-ts to npm

This package is published to npm as an ESM-only module with provenance via GitHub Actions OIDC.

## One-time setup

### 1. Create an npm account

If you don't have one, sign up at https://www.npmjs.com/signup.

### 2. Link the npm package to your GitHub repository

Go to https://www.npmjs.com/settings/YOUR_USERNAME/packages and verify that the `asn1-per-ts` package name is available (or already owned by you).

### 3. Generate an npm access token

1. Go to https://www.npmjs.com/settings/YOUR_USERNAME/tokens
2. Click **Generate New Token** → **Granular Access Token**
3. Configure:
   - **Token name**: `github-actions-publish`
   - **Expiration**: choose a duration (or no expiration)
   - **Packages and scopes**: select **Only select packages and scopes**, then pick `asn1-per-ts` (or "All packages" if the package doesn't exist yet)
   - **Permissions**: **Read and write**
4. Click **Generate Token** and copy the token value

### 4. Add the token to GitHub repository secrets

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `NPM_TOKEN`
4. Value: paste the npm token from the previous step
5. Click **Add secret**

### 5. Configure npm provenance (OIDC)

npm provenance is automatically enabled by the `--provenance` flag in the publish workflow. For this to work:

1. Go to your npm package settings at https://www.npmjs.com/package/asn1-per-ts/access (available after first publish)
2. Under **Publishing access**, ensure **Require two-factor authentication or an automation token** is selected
3. No additional OIDC configuration is needed on the npm side — npm trusts GitHub Actions OIDC tokens natively

On the GitHub side, the workflow already has `id-token: write` permission, which is all that's needed.

## Publishing a new version

Publishing is fully automated via GitHub releases. Follow these steps:

### 1. Bump the version

```bash
# For a patch release (bug fixes)
npm version patch

# For a minor release (new features, backwards compatible)
npm version minor

# For a major release (breaking changes)
npm version major
```

This updates `package.json`, creates a git commit, and creates a git tag (e.g., `v1.0.1`).

### 2. Push the commit and tag

```bash
git push origin main --follow-tags
```

### 3. Create a GitHub release

1. Go to https://github.com/sysdevrun/asn1-per-ts/releases/new
2. Select the tag you just pushed (e.g., `v1.0.1`)
3. Set the release title (e.g., `v1.0.1`)
4. Add release notes (or click **Generate release notes** for auto-generated notes)
5. Click **Publish release**

The `publish.yml` GitHub Action will automatically:
- Install dependencies
- Run tests
- Build the package
- Publish to npm with provenance

### 4. Verify

- Check the **Actions** tab for the workflow run status
- Verify the package on https://www.npmjs.com/package/asn1-per-ts
- The package page will show a **Provenance** badge linking the build back to the exact GitHub commit and workflow

## What gets published

Only the `dist/` directory (compiled ESM JavaScript + TypeScript declarations) is included in the npm package, along with `package.json`, `README.md`, and `LICENSE`.

Excluded from the npm package:
- `website/` (published separately to GitHub Pages)
- `intercode6-ts/` (separate module)
- `tests/`, `cli/`, `schemas/`, `examples/`
- Source TypeScript files (`src/`)
- Configuration files (`tsconfig.json`, `jest.config.cjs`, etc.)

## Package format

- **ESM only** (`"type": "module"`) — no CommonJS build
- Works in both **Node.js** (≥18) and **browsers** (via bundlers)
- Tree-shakeable (`"sideEffects": false`)
- Includes TypeScript declarations (`.d.ts`) and declaration maps

## Troubleshooting

### Publish fails with 403

- Verify the `NPM_TOKEN` secret is set correctly in GitHub repository settings
- Ensure the token has write access to the package
- Check if the package name is already taken by another user

### Publish fails with provenance error

- Ensure the workflow has `id-token: write` permission (already configured)
- Provenance requires the publish to happen directly in a GitHub Actions workflow (not from a fork)

### Tests fail in CI

- The workflow runs `npm test` before publishing. Fix failing tests before creating a release.
