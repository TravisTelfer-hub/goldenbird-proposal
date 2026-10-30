# Goldenbird x Webprofits proposal (encrypted Pages site)

Password-protected copy of the Goldenbird Cocktails proposal, served from `public/` by GitHub Pages. Every HTML page is a StatiCrypt blob that decrypts in the browser; the plaintext source lives in `public-encrypted/` on the author's machine only and is never committed.

- Live: https://travistelfer-hub.github.io/goldenbird-proposal/proposal/
- Password: one shared password for every page, kept in `.env` (`ENCRYPT_PASSWORD`, gitignored) and in 1Password. Never written into this repo.
- Source of truth for the content: `Claude Code/clients/prospects/goldenbird/` (`proposal-content.json` + `build_proposal.py`). Rebuild there, copy the pages into `public-encrypted/`, then `make encrypt` and push.
- Guard: `make release-check` (also runs on commit and in CI) refuses any plain HTML in `public/` other than the root redirect.
