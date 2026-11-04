#!/usr/bin/env python3
"""Import verified client executables from a stable GitHub Release."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
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


GITHUB_HOSTS = {'github.com', 'api.github.com', 'release-assets.githubusercontent.com',
                'objects.githubusercontent.com', 'github-releases.githubusercontent.com'}
ACCELERATOR_HOSTS = {'gh-proxy.com', 'gh-proxy.org'}


def version_key(version):
    return tuple(map(int, version.split('.')))


@contextlib.contextmanager
def cache_lock(directory, name='.release.lock', shared=False):
    descriptor = os.open(directory / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def file_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def older(version, latest):
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', version):
        return False
    return (version_key(version) + (0,) * 4)[:4] < (version_key(latest) + (0,) * 4)[:4]


def cleanup(database, now=None):
    """Prune committed obsolete metadata, then unlink only owned cache files.

    Optional coordination tables preserve compatibility with the core schema.
    A tombstone survives a failed unlink, so the periodic worker can retry it.
    """
    directory = database.parent / 'updates'
    directory.mkdir(mode=0o700, exist_ok=True)
    now = int(time.time()) if now is None else now
    raw_pattern = re.compile(r'(?:github-)?(?:windows|android|linux(?:-[a-z0-9_]+)?|macos(?:-[a-z0-9_]+)?)-'
                             r'([0-9]+(?:\.[0-9]+){0,3})-[0-9a-f]{64}')
    installer_pattern = re.compile(r'installer-[0-9a-f]{64}-([0-9a-f]{64})\.sh')
    result = {'records': 0, 'files': 0, 'deferred': 0}
    with cache_lock(directory), sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=5) as db:
        db.execute('CREATE TABLE IF NOT EXISTS package_leases(platform TEXT,version TEXT,expires_at INTEGER,PRIMARY KEY(platform,version))')
        db.execute('CREATE TABLE IF NOT EXISTS package_gc(filename TEXT PRIMARY KEY)')
        latest = db.execute('SELECT version FROM release_sync WHERE id=1').fetchone()
        if not latest:
            return result
        with db:
            db.execute('DELETE FROM package_leases WHERE expires_at<=?', (now,))
            deleted = set()
            for table in ('release_packages', 'updates'):
                for platform, version, filename in db.execute(f'SELECT platform,version,filename FROM {table}').fetchall():
                    if not older(version, latest[0]):
                        continue
                    if db.execute('SELECT 1 FROM package_leases WHERE platform=? AND version=? AND expires_at>?',
                                  (platform, version, now)).fetchone():
                        result['deferred'] += 1
                        continue
                    db.execute(f'DELETE FROM {table} WHERE platform=? AND version=?', (platform, version))
                    result['records'] += 1
                    deleted.add(filename)
            referenced = {row[0] for row in db.execute('SELECT filename FROM updates UNION SELECT filename FROM release_packages')}
            digests = {row[0] for row in db.execute('SELECT sha256 FROM updates UNION SELECT sha256 FROM release_packages')}
            for path in directory.iterdir():
                name = path.name
                match = raw_pattern.fullmatch(name)
                installer = installer_pattern.fullmatch(name)
                if name not in referenced and ((match and older(match[1], latest[0])) or
                                               (installer and installer[1] not in digests)):
                    deleted.add(name)
            for name in deleted - referenced:
                # A corrupt DB entry must never turn cleanup into a path traversal.
                if raw_pattern.fullmatch(name) or installer_pattern.fullmatch(name):
                    db.execute('INSERT OR IGNORE INTO package_gc VALUES(?)', (name,))
        for (name,) in db.execute('SELECT filename FROM package_gc').fetchall():
            if name in referenced:
                db.execute('DELETE FROM package_gc WHERE filename=?', (name,))
                continue
            if not (raw_pattern.fullmatch(name) or installer_pattern.fullmatch(name)):
                db.execute('DELETE FROM package_gc WHERE filename=?', (name,))
                continue
            try:
                path = directory / name
                if path.exists() and stat.S_ISDIR(path.lstat().st_mode):
                    raise OSError('cache entry is a directory')
                path.unlink(missing_ok=True)  # Unlink the entry, never a symlink's target.
            except OSError as error:
                result['deferred'] += 1
                print(f'Old package cleanup deferred for {name}: {error}', file=sys.stderr, flush=True)
            else:
                result['files'] += 1
                db.execute('DELETE FROM package_gc WHERE filename=?', (name,))
        db.commit()
    return result


class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, accelerated=False):
        self.allowed_hosts = GITHUB_HOSTS | (ACCELERATOR_HOSTS if accelerated else set())

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != 'https' or parsed.hostname not in self.allowed_hosts or
                parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443)):
            raise ValueError('unexpected GitHub download redirect')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def fetch(url, accept='application/vnd.github+json', accelerated=False):
    request = urllib.request.Request(url, headers={'User-Agent': 'FastP2P-gateway', 'Accept': accept})
    handlers = [GitHubRedirect(accelerated)]
    if accelerated:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers).open(request, timeout=20)


def validate_download_prefix(prefix):
    if not prefix:
        return ''
    parsed = urllib.parse.urlsplit(prefix)
    if (parsed.scheme != 'https' or parsed.netloc not in ACCELERATOR_HOSTS or
            parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('download prefix must be https://gh-proxy.com/ or https://gh-proxy.org/')
    return prefix.rstrip('/') + '/'


def release_page(url, download_prefix):
    routes = [(url, False)]
    if download_prefix:
        routes.insert(0, (download_prefix + url, True))
    for source, accelerated in routes:
        try:
            with fetch(source, accelerated=accelerated) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('GitHub release list is too large')
            rows = json.loads(data)
            if not isinstance(rows, list):
                raise ValueError('invalid GitHub release list')
            return rows
        except (OSError, ValueError) as error:
            if not accelerated:
                raise
            print(f'Accelerated release lookup failed; retrying GitHub API: {error}',
                  file=sys.stderr, flush=True)


def latest(repository, download_prefix=''):
    releases = []
    for page in range(1, 6):
        url = f'https://api.github.com/repos/{repository}/releases?per_page=100&page={page}'
        rows = release_page(url, download_prefix)
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


def download(repository, release, asset, path, expected=None, download_prefix=''):
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
    if path.exists():
        raise ValueError('download destination already exists')
    routes = [(api + f'?download=1&ts={time.time_ns()}', False)]
    # Accelerate the checksum file only when GitHub has supplied its digest.
    # The trust anchor is always independent of the accelerator.
    prefix = validate_download_prefix(download_prefix)
    if prefix and expected:
        routes.insert(0, (prefix + url, True))
    for source, accelerated in routes:
        try:
            with fetch(source, 'application/octet-stream', accelerated) as response:
                digest = copy_checked(response, path, asset['size'], expected)
            if accelerated:
                print(f'Verified accelerated download: {name}', flush=True)
            return digest
        except (OSError, ValueError) as error:
            path.unlink(missing_ok=True)
            if not accelerated:
                raise ValueError(f'{name}: {error}') from error
            print(f'Accelerated download failed for {name}; retrying GitHub API: {error}',
                  file=sys.stderr, flush=True)


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


def sync(database, repository, download_prefix=''):
    directory = database.parent / 'updates'
    directory.mkdir(mode=0o700, exist_ok=True)
    with cache_lock(directory, '.sync.lock'):
        version = import_release(database, repository, download_prefix)
        result = cleanup(database)
        print('Old client packages cleaned: ' + json.dumps(result), flush=True)
        return version


def import_release(database, repository, download_prefix=''):
    download_prefix = validate_download_prefix(download_prefix)
    version, release = latest(repository, download_prefix)
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
        cached = db.execute('SELECT platform,size,filename,sha256 FROM release_packages WHERE version=?',
                            (version,)).fetchall()
        with cache_lock(directory, shared=True):
            if (saved == (version, release['id']) and {row[0] for row in cached} == selected.keys() and
                    all((directory / name).is_file() and (directory / name).stat().st_size == size and
                        file_digest(directory / name) == sha for _, size, name, sha in cached)):
                return version

        with tempfile.TemporaryDirectory(prefix='.github-', dir=directory) as tmp:
            staging = Path(tmp)
            manifest = staging / checksum['name']
            download(repository, release, checksum, manifest, download_prefix=download_prefix)
            sums = {}
            for line in manifest.read_text(encoding='ascii').splitlines():
                match = re.fullmatch(r'([0-9a-f]{64})\s+([A-Za-z0-9_.-]+)', line)
                if not match or match[2] in sums:
                    raise ValueError('invalid or duplicate SHA256SUMS.txt entry')
                sums[match[2]] = match[1]
            packages = []
            for platform, (name, member) in selected.items():
                path = staging / name
                digest = download(repository, release, assets[name], path, sums[name], download_prefix)
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
            with cache_lock(directory):
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
    parser.add_argument('--download-prefix', default=os.environ.get('FASTP2P_RELEASE_DOWNLOAD_PREFIX', ''))
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('repository must be owner/name')
    try:
        if args.cleanup_only:
            print('Old client packages cleaned: ' + json.dumps(cleanup(args.database.absolute())), flush=True)
            return 0
        version = sync(args.database.absolute(), args.repository, args.download_prefix)
    except (OSError, ValueError, KeyError, sqlite3.Error, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f'GitHub client release sync failed: {error}', file=sys.stderr)
        return 1
    print(f'GitHub client release synced: {version}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
