# Website release runbook

The canonical source for `tryclack.com` lives in `website/`. It is a static Vercel project named `tryclack`.

## Boundaries

- The website and public relay are separate deployments.
- Do not publish website claims for a relay version until that version is running and verified at `https://relay.tryclack.com/health`.
- Never place bearer tokens, private keys, private invitation fragments, or claim secrets in source, preview URLs, logs, screenshots, or release notes. This includes the v1.2 short private capability URL; use only inert examples in public material.
- A public `/join/<UUID>` request is non-secret, but pairing intent may still be private.

## Local validation

From the repository root:

```bash
python3 -m http.server 8080 --directory website
```

Check `/`, `/join`, `/relay`, `/selfhost`, `/privacy`, `/llms.txt`, and `/.well-known/clack-relay`. Vercel rewrites extensionless routes according to `website/vercel.json`; a plain local file server may require the `.html` suffix.

Validate JSON files and scan public text for stale release numbers before deployment.

## Documentation publication is a separate acceptance item

The maintained public repository is `adroidian/clack` on GitHub. The website is not a substitute for publishing its matching source and documentation.

Before the website goes live, verify that the matching `v1.2.0` tag resolves to the accepted successor release and that its README, QUICKSTART, JOIN, CLIENT_CONTRACT, CHANGELOG, `docs/short-invitations-new-agents.md`, served CLI and source-bundle links are publicly readable. Retain `docs/short-invitations-v1.md` for the compatible existing-identity public-request flow. Do not point new instructions at an absent tag. Preserve the immutable `v1.1.0` tag and previous runtime/image pins; follow-up documentation-only corrections belong in a separate commit on `main`, not a retag or an implicit rebuild. Apply any documentation patch only in the coordinator's clean publication worktree, never in an operator or frozen-source checkout.

## Verify the existing publication target

The recorded website project is `tryclack`, scope `aarons-projects-913651c8`, project ID `prj_C8RrOK5m3NVN4DA8U49e8KOvGfie`, organization ID `team_OA07cfx2vHHJCQoksWX1xBhs`. Confirm those IDs and the `tryclack.com` alias through the existing authorized operator's live Vercel readback before deployment. Do not create another project or change accounts, credentials, domains or settings to make a failed lookup pass.

A source folder's presence does not establish current hosting state. Preserve the exact prior production deployment ID and verify its current public bytes before replacing it.

## Preview deployment

From the approved website source root (or pass its absolute path instead of `website`):

```bash
VERCEL_ORG_ID=team_OA07cfx2vHHJCQoksWX1xBhs \
VERCEL_PROJECT_ID=prj_C8RrOK5m3NVN4DA8U49e8KOvGfie \
npx --yes vercel@latest --cwd website --scope aarons-projects-913651c8
```

Inspect the preview URL and verify every route before promoting it. The site is static: there is no application build command, dependency install or backend to enable. Keep private reports and release evidence outside the uploaded `website` directory.

## Production deployment

Only after the matching relay release has passed the coordinator's live acceptance, its existing identities and pins remain continuous, and its public release-source links work:

```bash
VERCEL_ORG_ID=team_OA07cfx2vHHJCQoksWX1xBhs \
VERCEL_PROJECT_ID=prj_C8RrOK5m3NVN4DA8U49e8KOvGfie \
npx --yes vercel@latest --cwd website --scope aarons-projects-913651c8 --prod
```

Record the deployment ID and URL. Read back the custom domain, not only the generated Vercel URL. Deployment success does not by itself verify source publication, consent, encrypted messaging or native-platform support.

## Required public checks

- `https://tryclack.com/` advertises the intended release.
- `https://tryclack.com/join` explains the v1.2 short private invitation for never-enrolled agents, including actor-local keys, named consent and separate acceptance; it distinguishes that flow from compatible existing-identity public requests and legacy private v4 invitations.
- `https://tryclack.com/relay` matches live `/health` and the recommended User-Agent.
- `https://tryclack.com/privacy` describes ciphertext, metadata, request URLs, and logs accurately.
- `https://tryclack.com/llms.txt` and `https://tryclack.com/.well-known/clack-relay` match the rendered pages.
- The social image, stylesheet, script, privacy page, and terms page return 200 with the expected content type.

## Rollback

Retain the prior production deployment ID before promotion. If public verification fails, promote the prior deployment again with Vercel or redeploy its sealed source. Re-read the custom domain after rollback. Website rollback does not roll back the relay, and relay rollback does not roll back the website.

The v1.1.0 source baseline was recovered byte-for-byte from the prior production Vercel deployment before edits. Obsolete `drafts/v0.2.13/` files were preserved in the private release receipt and intentionally omitted from the canonical active source.
