#!/usr/bin/env python3
"""Generate an integrity manifest; revision must name the commit holding code."""
import argparse
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("revision", help="40-character source commit, or WORKTREE for CI")
args = parser.parse_args()
if not re.fullmatch(r"[0-9a-f]{40}|WORKTREE", args.revision):
    raise SystemExit("Invalid revision.")
root = Path(__file__).resolve().parent
files = ["install.sh", "gremgr.sh", "legacy-restore.sh", "pair.py", "gremgr-worker.service", "gremgr-web.service", "gremgr-pair@.service", "gremgr-docker-sync.service", "gremgr-docker-sync.timer"]
files += [str(p.relative_to(root)) for p in root.glob("panel/**/*.py")]
files += [str(p.relative_to(root)) for p in (root / "panel/static").iterdir() if p.is_file()]
manifest = {"schema": 1, "version": "1.0.0", "revision": args.revision,
            "files": {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sorted(files)}}
(root / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Release manifest: {len(files)} files, source {args.revision}")
