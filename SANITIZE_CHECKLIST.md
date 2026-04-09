# Clack Sanitization Checklist

Before syncing this repo to GitHub, verify all of the following:

## Secrets
- [ ] no real auth tokens
- [ ] no bearer tokens
- [ ] no gateway tokens
- [ ] no Cloudflare / tunnel tokens
- [ ] no API keys

## Infrastructure identifiers
- [ ] no real domains
- [ ] no real IPs
- [ ] no local LAN addresses
- [ ] no Tailscale addresses
- [ ] no Cloud Run URLs
- [ ] no personal filesystem paths

## Identity / org references
- [ ] no private agent names unless intentionally kept generic
- [ ] no internal org/project names that should stay private
- [ ] no personal usernames or account IDs

## Files to double-check manually
- [ ] `router.js`
- [ ] `clack_server.py`
- [ ] `config.example.json`
- [ ] commit history before mirroring

## Release bar
- [ ] fresh repo with clean history
- [ ] README understandable by outsiders
- [ ] setup can succeed without private infrastructure
- [ ] examples use placeholders only