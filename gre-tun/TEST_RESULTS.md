# Actual tests — 2026-10-17

- Contract suite: **34 passed**.
- Additional development tests: **13 passed**.
- Total automated offline unit and contract tests: **47 passed**.
- Python source syntax: passed local compileall check.
- Bash syntax: passed `bash -n` for installer and launcher.
- Frozen schemas, examples, menus and manifest: verified with `tests/verify_package.py`.
- Live GRE/nft/tc forwarding and rollback: **NOT RUN**; code not yet implemented, no isolated netns/VM validation.
- Installer on Ubuntu 22.04/24.04: **NOT RUN**; sandbox host is not a deployment VM.
- Remote GitHub installation: **NOT RUN**; publishing must be verified first.
