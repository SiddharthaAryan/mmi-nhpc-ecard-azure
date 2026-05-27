# MMI NHPC E-Card Azure

Azure-ready rebuild of the MMI Narayana Health Family Privilege Card prototype.

## What this version changes

- Frontend does **not** connect directly to any database.
- Public pages call `/api/*` Azure Functions.
- Azure Functions write to Azure Table Storage.
- Phone numbers and names are encrypted before storage.
- Phone matching uses a keyed hash, not plain phone lookup.
- QR verification returns only minimal public data.
- Admin dashboard requires Azure Static Web Apps authentication plus a server-side email allowlist.
- No Firebase config, database key, or storage connection string is present in public code.

## Architecture

```text
GitHub repo
   ↓
Azure Static Web Apps
   ↓
Azure Functions API
   ↓
Azure Table Storage
```

## Azure Static Web Apps setup

When creating the Azure Static Web App, use:

```text
App location: /
API location: api
Output location: leave blank
```

## Required Azure Application Settings

Add these in Azure Static Web Apps → Configuration → Application settings:

```text
AZURE_STORAGE_CONNECTION_STRING=<storage account connection string>
FIELD_ENCRYPTION_KEY_BASE64=<32-byte base64 key>
HASH_SECRET=<long random secret>
ADMIN_EMAILS=aryansiddhartha03@gmail.com,ravi.bhagat@narayanahealth.org
CARD_PREFIX=NHPC-AZ
TABLE_NAME=NhpcCards
```

Generate encryption key locally:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Generate hash secret locally:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## Important governance note

This is a controlled prototype structure. For official hospital rollout, deploy it under an NH-approved Azure tenant/subscription and get NH IT review before collecting live patient/lead data at scale.

## Pages

- `/index.html` — public e-card generation
- `/verify.html?id=NHPC-AZ-XXXX` — QR verification
- `/security.html` — admin dashboard
- `/bulk-generator.html` — admin bulk e-card package generator

## Data minimization

Do not store diagnosis, UHID, IPD/OPD number, clinical notes, or medical history in this system unless NH IT formally approves it.
