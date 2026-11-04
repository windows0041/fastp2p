#!/usr/bin/env python3
"""Import verified client executables from a stable GitHub Release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

LIMIT = 128 * 1024 * 1024
TAG = re.compile(r'fastp2p-client-v((?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2})')
LINUX = ('x86_64', 'aarch64', 'armv7', 'i686', 'riscv64', 's390x', 'ppc64le', 'mips64el')
ASSETS = {
    'fastp2p-windows-x86_64.exe': ('windows', None),
    'fastp2p-windows-x86_64.zip': ('windows', 'fastp2p.exe'),
    'fastp2p-android.apk': ('android', None),
    **{f'fastp2p-linux-static-{arch}.tar.gz':
       (f'linux-{arch}', f'fastp2p-linux-static-{arch}/bin/fastp2p') for arch in LINUX},
    **{f'fastp2p-macos-{arch}.tar.gz':
       (f'macos-{arch}', f'macos-{arch}/bin/fastp2p') for arch in ('arm64', 'x86_64')},
}


def version_key(version):
    return tuple(map(int, version.split('.')))


class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname not in {
                'github.com', 'api.github.com', 'release-assets.githubusercontent.com',
                'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}:
            raise ValueError('unexpected GitHub download redirect')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def fetch(url, accept='application/vnd.github+json'):
    request = urllib.request.Request(url, headers={'User-Agent': 'FastP2P-gateway', 'Accept': accept})
    return urllib.request.build_opener(GitHubRedirect).open(request, timeout=20)


def latest(repository):
    releases = []
    for page in range(1, 6):
        url = f'https://api.github.com/repos/{repository}/releases?per_page=100&page={page}'
        with fetch(url) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('GitHub release list is too large')
        rows = json.loads(data)
        if not isinstance(rows, list):
            raise ValueError('invalid GitHub release list')
        for release in rows:
            match = TAG.fullmatch(release['tag_name'])
            if match and not release['draft'] and not release['prerelease']:
                releases.append((match[1], release))
        if len(rows) < 100:
            break
    else:
        raise ValueError('too many GitHub releases to safely determine the latest version')
    if not releases:
        raise ValueError('no stable fastp2p client release found')
    return max(releases, key=lambda item: version_key(item[0]))


def copy_checked(source, path, size, expected=None):
    if not 0 < size <= LIMIT:
        raise ValueError('invalid package size')
    digest = hashlib.sha256()
    written = 0
    with path.open('xb') as output:
        while chunk := source.read(65536):
            written += len(chunk)
            if written > size:
                raise ValueError('package exceeds declared size')
            output.write(chunk)
            digest.update(chunk)
    actual = digest.hexdigest()
    if written != size or (expected is not None and actual != expected):
        raise ValueError('package size or SHA-256 mismatch')
    return actual


def download(repository, release, asset, path, expected=None):
    name = asset['name']
    url = f"https://github.com/{repository}/releases/download/{release['tag_name']}/{name}"
    asset_id = asset['id']
    api = f'https://api.github.com/repos/{repository}/releases/assets/{asset_id}'
    if (not isinstance(asset_id, int) or asset_id <= 0 or asset['state'] != 'uploaded' or
            asset['browser_download_url'] != url or asset['url'] != api):
        raise ValueError('invalid release asset metadata')
    github_digest = asset.get('digest')
    if github_digest:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', github_digest):
            raise ValueError('invalid GitHub asset digest')
        if expected and github_digest != 'sha256:' + expected:
            raise ValueError('GitHub digest differs from SHA256SUMS.txt')
        expected = github_digest[7:]
    try:
        with fetch(api + f'?download=1&ts={time.time_ns()}', 'application/octet-stream') as response:
            return copy_checked(response, path, asset['size'], expected)
    except (OSError, ValueError) as error:
        raise ValueError(f'{name}: {error}') from error


def extract(asset, member, output):
    if asset.suffix == '.zip':
        with zipfile.ZipFile(asset) as archive:
            names = [entry for entry in archive.infolist() if not entry.is_dir() and
                     entry.filename in (member, 'windows-x86_64/' + member,
                                        'windows-x86_64/bin/' + member)]
            if len(names) != 1:
                raise ValueError('missing or ambiguous Windows executable')
            with archive.open(names[0]) as source:
                return copy_checked(source, output, names[0].file_size)
    with tarfile.open(asset, 'r|gz') as archive:
        for entry in archive:
            if entry.name == member and entry.isfile():
                with archive.extractfile(entry) as source:
                    return copy_checked(source, output, entry.size)
    raise ValueError('executable missing from release archive')


def sync(database, repository):
    version, release = latest(repository)
    assets = {asset['name']: asset for asset in release['assets']}
    checksum = assets['SHA256SUMS.txt']
    if not 0 < checksum['size'] <= 65536:
        raise ValueError('invalid SHA256SUMS.txt size')
    selected = {}
    for name, (platform, member) in ASSETS.items():
        if name in assets and platform not in selected:
            selected[platform] = (name, member)
    if not {'windows', 'android', 'linux-x86_64', 'macos-arm64', 'macos-x86_64'} <= selected.keys():
        raise ValueError('stable client release has missing installation packages')

    directory = database.parent / 'updates'
    directory.mkdir(mode=0o700, exist_ok=True)
    with sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=5) as db:
        saved = db.execute('SELECT version,release_id FROM release_sync WHERE id=1').fetchone()
        if saved and version_key(saved[0]) > version_key(version):
            raise ValueError('GitHub stable version is older than the cached release')
        cached = db.execute('SELECT platform,size,filename FROM release_packages WHERE version=?',
                            (version,)).fetchall()
        if (saved == (version, release['id']) and {row[0] for row in cached} == selected.keys() and
                all((directory / name).is_file() and (directory / name).stat().st_size == size
                    for _, size, name in cached)):
            return version

        with tempfile.TemporaryDirectory(prefix='.github-', dir=directory) as tmp:
            staging = Path(tmp)
            manifest = staging / checksum['name']
            download(repository, release, checksum, manifest)
            sums = {}
            for line in manifest.read_text(encoding='ascii').splitlines():
                match = re.fullmatch(r'([0-9a-f]{64})\s+([A-Za-z0-9_.-]+)', line)
                if not match or match[2] in sums:
                    raise ValueError('invalid or duplicate SHA256SUMS.txt entry')
                sums[match[2]] = match[1]
            packages = []
            for platform, (name, member) in selected.items():
                path = staging / name
                digest = download(repository, release, assets[name], path, sums[name])
                if member:
                    output = staging / platform
                    digest = extract(path, member, output)
                    path.unlink()
                    path = output
                filename = f'github-{platform}-{version}-{digest}'
                packages.append((path, (platform, version, digest, path.stat().st_size,
                                        filename, int(time.time()))))

            # Files are prepared and verified before SQLite publishes any row.
            # Content-based names keep downloads of the previous release valid.
            for path, row in packages:
                path.replace(directory / row[4])
            with db:
                db.executemany('INSERT INTO release_packages VALUES(?,?,?,?,?,?) '
                               'ON CONFLICT(platform,version) DO UPDATE SET sha256=excluded.sha256,'
                               'size=excluded.size,filename=excluded.filename,uploaded_at=excluded.uploaded_at',
                               [row for _, row in packages])
                db.execute('INSERT INTO release_sync VALUES(1,?,?) ON CONFLICT(id) '
                           'DO UPDATE SET version=excluded.version,release_id=excluded.release_id',
                           (version, release['id']))
    return version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--repository', default='windows0041/fastp2p')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('repository must be owner/name')
    try:
        version = sync(args.database.absolute(), args.repository)
    except (OSError, ValueError, KeyError, sqlite3.Error, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f'GitHub client release sync failed: {error}', file=sys.stderr)
        return 1
    print(f'GitHub client release synced: {version}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
