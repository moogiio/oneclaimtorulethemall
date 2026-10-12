# OneClaimToRuleThemAll

Build AD FS claim rules by clicking instead of writing claim rule language by hand.

## Features

- A guided setup for new applications and identity providers, and a welcome with an example to look around in
- Applications (relying party trusts) and identity providers (claims provider trusts), created by the export when AD FS does not have them yet, from a metadata URL, a metadata file or by hand
- A metadata file is read in the browser: it shows the identifier, sign-in URL and Name ID, and adds the claims the application asks for
- Plain-language steps: who gets access, claims to send, claims to accept, with every rule explained in plain words
- Access by built-in access control policy or by rules
- Quick starts and templates for well-known apps
- A setup checklist per application and an AD FS glossary
- Rule library with linked rules: change once, applies everywhere
- Conditions: AD group membership (by name or SID), corporate network, MFA or any claim
- Builders for complex rules: look up several claims in any attribute store, and translate values case by case like a switch (paste the list from Excel)
- Linter with one-click fixes for common claim rule mistakes
- Try it: simulate a sign-in for a test user and see every rule's result and the token
- Sign-in fails? Paste the AD FS error page or event: it is explained in plain words, with what to do and a click to the setting that fixes it
- Import a whole AD FS farm with a read-only script, or compare it with the workspace to see what differs, or import single rule files
- Export one PowerShell script for the AD FS admin, per application or for all: it shows the changes and asks before applying. Or follow the same as steps in AD FS Management
- Undo and redo

## Run locally

Requires Node.js 20 or later.

```bash
npm install
npm run dev
```

Open http://127.0.0.1:3000 and create a workspace.
