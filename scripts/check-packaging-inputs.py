#!/usr/bin/env python3
"""Fail in seconds when a packaging input is missing, instead of after a 15 minute build.

Every packaging step that has broken since the split did so by naming a file that no
longer exists (NODE-STORAGE-ZH.md, common/bootstrap.json, c/client paths). Those are all
static facts about the tree, so they can be checked before anything compiles.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
problems = []

# 1. documents and files the SDK packaging copies
SDK_INPUTS = ['LICENSE', 'README.md', 'PLATFORMS-ZH.md', 'SOCKS5-ZH.md', 'THIRD_PARTY.md',
              'config.example.json', 'config.socks5.example.json', 'deps.lock.json',
              'include/fastp2p.h', 'examples/embed.c', 'common/bootstrap.json']
for name in SDK_INPUTS:
    if not (REPO/name).exists():
        problems.append('packaging input missing: ' + name)

# 2. the release publisher's provenance list must exist too
publisher = (REPO/'scripts/publish-release.py')
if publisher.exists():
    text = publisher.read_text(encoding='utf-8')
    match = re.search(r"\['client':[^]]*?\[([^\]]+)\]", text, re.S)
    if match:
        for entry in re.findall(r"'([^']+)'", match.group(1)):
            if not (REPO/entry).exists():
                problems.append('publisher path missing: ' + entry)

# 3. no monorepo-era paths in code or workflows
pattern = re.compile(r'c[\\/](client|gateway|common)')
scan = list((REPO/'scripts').rglob('*')) + list((REPO/'.github').rglob('*'))
for path in sorted(p for p in scan if p.resolve() != Path(__file__).resolve()):
    if not path.is_file() or path.suffix in {'.md', '.png'}:
        continue
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        continue
    for number, line in enumerate(text.splitlines(), 1):
        if pattern.search(line) and 'src/client.c' not in line:
            problems.append('%s:%d still names the monorepo' % (path.relative_to(REPO), number))

if problems:
    print('preflight failed:')
    for item in problems:
        print('  -', item)
    sys.exit(1)
print('preflight ok: every packaging input exists and no monorepo paths remain')
