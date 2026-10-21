# Website release runbook

The canonical source for `tryclack.com` lives in `website/`. It is a static Vercel project named `tryclack`.

## Boundaries

- The website and public relay are separate deployments.
- Do not publish website claims for a relay version until that version is running and verified at `https://relay.tryclack.com/health`.
- Never place bearer tokens, private keys, v4 invitation fragments, or claim secrets in source, preview URLs, logs, screenshots, or release notes.
- A public `/join/<UUID>` request is non-secret, but pairing intent may still be private.

## Local validation

From the repository root:

```bash
python3 -m http.server 8080 --directory website
```

Check `/`, `/join`, `/relay`, `/selfhost`, `/privacy`, `/llms.txt`, and `/.well-known/clack-relay`. Vercel rewrites extensionless routes according to `website/vercel.json`; a plain local file server may require the `.html` suffix.

Validate JSON files and scan public text for stale release numbers before deployment.

## Preview deployment

```bash
npx --yes vercel@latest --cwd website
```

Inspect the preview URL and verify every route before promoting it.

## Production deployment

After the matching relay release is live and verified:

```bash
npx --yes vercel@latest --cwd website --prod
```

Record the deployment ID and URL. Read back the custom domain, not only the generated Vercel URL.

## Required public checks

- `https://tryclack.com/` advertises the intended release.
- `https://tryclack.com/join` distinguishes new-identity v4 capabilities from existing-identity short requests.
- `https://tryclack.com/relay` matches live `/health` and the recommended User-Agent.
- `https://tryclack.com/privacy` describes ciphertext, metadata, request URLs, and logs accurately.
- `https://tryclack.com/llms.txt` and `https://tryclack.com/.well-known/clack-relay` match the rendered pages.
- The social image, stylesheet, script, privacy page, and terms page return 200 with the expected content type.

## Rollback

Retain the prior production deployment ID before promotion. If public verification fails, promote the prior deployment again with Vercel or redeploy its sealed source. Re-read the custom domain after rollback. Website rollback does not roll back the relay, and relay rollback does not roll back the website.

The v1.1.0 source baseline was recovered byte-for-byte from the prior production Vercel deployment before edits. Obsolete `drafts/v0.2.13/` files were preserved in the private release receipt and intentionally omitted from the canonical active source.
