#!/usr/bin/env python3
"""Verify release provenance paths and provide CI with the release architecture matrix."""
import json
import os
from pathlib import Path
import re
import runpy


def main():
    script = Path(__file__).resolve()
    repo = script.parents[1]
    publisher = runpy.run_path(str(script.with_name('publish-release.py')))
    problems = [
        f'publisher path missing: {name}' for name in publisher['CLIENT_SOURCE_PATHS']
        if not (repo / name).exists()
    ]
    old_path = re.compile(r'(?<![\w/\\])c[/\\](client|gateway|common)\b')
    for directory in (repo / 'scripts', repo / '.github' / 'workflows'):
        for path in sorted(directory.rglob('*')):
            if path.resolve() == script or path.suffix not in {'.py', '.sh', '.yaml', '.yml'}:
                continue
            for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if old_path.search(line):
                    problems.append(f'{path.relative_to(repo)}:{number} still names the monorepo')
    if problems:
        raise SystemExit('Preflight failed:\n  - ' + '\n  - '.join(problems))

    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with Path(output).open('a', encoding='utf-8') as stream:
            print('musl_arches=' + json.dumps(publisher['CLIENT_MUSL_ARCHES']), file=stream)
    print('Release provenance paths verified')


if __name__ == '__main__':
    main()
