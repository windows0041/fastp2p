#!/usr/bin/env python3
"""Include headers, examples, locked-source notices and runtime-free sample config."""
import argparse
import json
from pathlib import Path
import shutil

PROJECT = Path(__file__).resolve().parents[1]
SDK_FILES = {
    name: name for name in (
        'LICENSE', 'README.md', 'PLATFORMS-ZH.md', 'SOCKS5-ZH.md', 'THIRD_PARTY.md',
        'NODE-STORAGE-ZH.md', 'NAT-TRAVERSAL-ZH.md', 'VALIDATION-ZH.md', 'UPGRADE-ZH.md',
        'WINDOWS-INSTALL-ZH.md', 'docs/tcp-punch.md', 'docs/performance-20261112.md',
        'config.example.json', 'config.socks5.example.json', 'deps.lock.json',
        'include/fastp2p.h', 'examples/embed.c',
    )
}
SDK_FILES['common/bootstrap.json'] = 'gateway-public.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--sdk', type=Path)
    operation.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--work', type=Path, default=Path.home() / 'fastp2p-dev/cross')
    args = parser.parse_args()

    missing = [name for name in SDK_FILES if not (PROJECT / name).is_file()]
    if missing:
        parser.error('missing SDK packaging inputs: ' + ', '.join(missing))
    if args.check_inputs:
        print('SDK packaging inputs verified')
        return

    sdk = args.sdk.resolve()
    for name, destination in SDK_FILES.items():
        target = sdk / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT / name, target)

    notices = sdk / 'licenses'
    notices.mkdir(exist_ok=True)
    manifest = json.loads((PROJECT / 'deps.lock.json').read_text(encoding='utf-8'))
    for name, item in manifest.items():
        source = args.work / 'sources' / f"{name}-{item['version']}"
        filename = Path(item.get('license', 'LICENSE.txt' if name == 'openssl' else 'COPYING'))
        shutil.copyfile(source / filename, notices / f'{name}-{filename.name}')
    print('SDK metadata and third-party licenses:', sdk)


if __name__ == '__main__':
    main()
