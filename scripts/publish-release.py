#!/usr/bin/env python3
"""Package allowlisted CI artifacts and publish a complete GitHub Release.

Use a draft until every asset uploads. No third-party publishing action or PAT is
needed in Actions: the release job receives contents:write for GITHUB_TOKEN.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

CLIENT_MUSL_ARCHES = ('x86_64', 'aarch64', 'armv7', 'riscv64', 'mips64el')
CLIENT_SOURCE_PATHS = (
    'common', 'src', 'include', 'cmake', 'platform', 'deps.lock.json', 'CMakeLists.txt',
    'android/app/src/main', 'android/app/src/androidTest', 'android/jni', 'android/app/build.gradle',
    'android/build.gradle', 'android/settings.gradle', 'android/gradle.properties', 'android/gradle',
)

KINDS = {
    'gateway': ('fastp2p-gateway', 'CMakeLists.txt', [
        'fastp2p-gateway-linux-static-x86_64.tar.gz',
        'fastp2p-gateway-linux-static-aarch64.tar.gz',
        'fastp2p-gateway-docker-amd64.tar.gz']),
    'client': ('fastp2p-client', 'CMakeLists.txt', [
        'fastp2p-sdk-linux-x86_64.tar.gz', 'fastp2p-windows-x86_64.exe',
        'fastp2p-macos-arm64.tar.gz', 'fastp2p-macos-x86_64.tar.gz',
        'fastp2p-android.apk',
        *(f'fastp2p-linux-static-{arch}.tar.gz' for arch in CLIENT_MUSL_ARCHES)])
}

def prepare(kind, incoming, output, without_android=False):
    output.mkdir(parents=True, exist_ok=True)
    result = []
    for name in KINDS[kind][2]:
        if without_android and name == 'fastp2p-android.apk':
            continue
        matches = [p for p in incoming.rglob(name) if p.is_file()]
        if len(matches) != 1 or matches[0].is_symlink() or matches[0].stat().st_size == 0:
            raise RuntimeError('Expected exactly one nonempty CI artifact: ' + name)
        target = output/name
        shutil.copyfile(matches[0], target)
        result.append(target)
    checksum = output/'SHA256SUMS.txt'
    checksum.write_text(''.join(digest(p) + '  ' + p.name + '\n'
                               for p in sorted(result)), encoding='utf-8', newline='\n')
    return result + [checksum]

class GitHub:
    def __init__(self, repository, token):
        self.repository, self.token = repository, token
    def request(self, path, data=None, method='GET', content_type='application/json'):
        url = path if path.startswith('https://uploads.github.com/') else 'https://api.github.com/repos/' + self.repository + path
        if not (url.startswith('https://api.github.com/repos/' + self.repository + '/') or
                url.startswith('https://uploads.github.com/repos/' + self.repository + '/')):
            raise RuntimeError('Unexpected GitHub API endpoint')
        if data is not None and not isinstance(data, bytes): data = json.dumps(data).encode()
        request = urllib.request.Request(url, data=data, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'Content-Type': content_type, 'User-Agent': 'FastP2P-release-builder'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=180) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as error:
            # GitHub explains permission and rate-limit refusals in the body; without
            # it a 403 in CI is indistinguishable from a dozen other causes.
            try:
                detail = error.read().decode('utf-8', 'replace')[:500]
            except Exception:
                detail = '(no body)'
            raise urllib.error.HTTPError(
                error.url, error.code,
                '%s %s -> %s: %s' % (method, path, error.reason, detail),
                error.headers, None) from None

def publish(kind, files, repository, sha, ref, ref_type, run_id, token, explicit_tag=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[0-9a-f]{40}',sha) or not run_id.isdigit():
        raise RuntimeError('Invalid release provenance')
    prefix, cmake, _ = KINDS[kind]
    source = subprocess.check_output(['git', 'show', sha + ':' + cmake], text=True)
    version = re.search(r'project\([^\n]+\bVERSION\s+(\d+\.\d+\.\d+)', source).group(1)
    stable = ref_type == 'tag' or explicit_tag is not None
    tag = explicit_tag or (ref if stable else prefix + '-dev-' + run_id + '-' + sha[:7])
    if stable and tag != prefix + '-v' + version:
        raise RuntimeError('Release tag must match the compiled project version')
    if not re.fullmatch(r'[a-z0-9][a-zA-Z0-9._-]{0,100}', tag):
        raise RuntimeError('Invalid release tag')
    if not stable and ref != 'main':
        raise RuntimeError('Development releases are restricted to main')
    api = GitHub(repository, token)
    if stable:
        tag_sha = subprocess.check_output(['git', 'rev-parse', tag + '^{commit}'], text=True).strip()
        paths = (['common','src','web','deploy','CMakeLists.txt','scripts/embed-web.py','Dockerfile'] if kind=='gateway' else
                 CLIENT_SOURCE_PATHS)
        if subprocess.run(['git','diff','--quiet',sha,tag_sha,'--',*paths]).returncode:
            raise RuntimeError('Tag runtime source differs from the tested build')
    if kind == 'gateway':
        notes = 'C 网关内嵌 Web 控制台，提供 HTTPS/WSS、NAT 探测及连接协调。提供 x86_64 和 aarch64 静态包以及 amd64 Docker 镜像。'
    else:
        arches = '、'.join(CLIENT_MUSL_ARCHES)
        notes = f'提供 Linux {arches} 静态包、Linux C SDK、Windows EXE 和 macOS 双架构包。'
        if any(file.name == 'fastp2p-android.apk' for file in files):
            notes += '本次发布包含正式签名的 Android APK。'
        else:
            notes += 'Android 调试 APK 可从对应的 Actions 运行下载。'

    body = notes + '\n\n构建提交：`' + sha + '`\n\n[GitHub 构建与测试](https://github.com/' + repository + '/actions/runs/' + run_id + ')\n\n下载后使用 `SHA256SUMS.txt` 校验。专用客户端包含网关地址和公开 CA；账号、接入 Token 和私钥不在发行包中。'
    metadata = {'tag_name': tag, 'target_commitish': sha,
                'name': ('fastp2p Gateway ' if kind == 'gateway' else 'fastp2p Client ') + version + ('' if stable else ' · development ' + run_id),
                'body': body, 'draft': True, 'prerelease': not stable}
    try:
        release = api.request('/releases/tags/' + urllib.parse.quote(tag, safe=''))
    except urllib.error.HTTPError as error:
        if error.code != 404: raise
        release = api.request('/releases', metadata, method='POST')
    existing = {a['name']: a for a in release['assets']}
    if not release['draft']:
        # Published assets are immutable to this script. A rerun may only verify.
        if set(existing) != {p.name for p in files}: raise RuntimeError('Published release asset set differs; refusing replacement')
        if any(a.get('state') != 'uploaded' or not a.get('size') for a in existing.values()):
            raise RuntimeError('Published release has incomplete assets')
        print('Release already complete:', release['html_url']); return
    upload = release['upload_url'].split('{', 1)[0]
    for file in files:
        if file.name in existing:
            asset = existing[file.name]
            file_digest = 'sha256:' + digest(file)
            if asset.get('digest') == file_digest: continue
            api.request('/releases/assets/' + str(asset['id']), method='DELETE')
        uploaded = api.request(upload + '?name=' + urllib.parse.quote(file.name, safe=''), file.read_bytes(),
                    method='POST', content_type='application/octet-stream')
        if uploaded.get('size') != file.stat().st_size or uploaded.get('digest') != 'sha256:' + digest(file):
            raise RuntimeError('GitHub asset checksum verification failed: ' + file.name)
        print('Uploaded:', file.name)
    # GitHub has one "Latest" badge per repository and it belongs to the newest
    # client. The gateway is a server component: publishing it must never take the
    # badge away from the client release that users download.
    newest = kind == 'client'
    release = api.request('/releases/' + str(release['id']),
                          {'draft': False, 'prerelease': not stable,
                           'make_latest': 'true' if stable and newest else 'false'},
                          method='PATCH')
    print('Published:', release['html_url'])
    if not stable:
        prune_development_releases(api, prefix + '-dev-', keep=2)

def prune_development_releases(api, prefix, keep):
    """Drop older development builds so CI output does not accumulate."""
    try:
        releases = api.request('/releases?per_page=100')
    except urllib.error.HTTPError as error:
        print('Skipped development cleanup:', error.code)
        return
    matching = [r for r in releases if r['tag_name'].startswith(prefix)]
    for release in sorted(matching, key=lambda r: r['created_at'], reverse=True)[keep:]:
        try:
            api.request('/releases/' + str(release['id']), method='DELETE')
            print('Removed old development release:', release['tag_name'])
        except urllib.error.HTTPError as error:
            print('Could not remove', release['tag_name'], error.code)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kind', choices=KINDS, required=True)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-only', action='store_true')
    p.add_argument('--tag')
    p.add_argument('--without-android', action='store_true',
                   help='Prepare an unsigned development run with desktop assets only')
    args = p.parse_args()
    if args.without_android and (
        args.kind != 'client' or args.tag or os.environ.get('GITHUB_REF_TYPE') == 'tag'
    ):
        p.error('--without-android is only available for client development builds')
    files = prepare(args.kind, args.input, args.output, args.without_android)
    if not args.prepare_only:
        publish(args.kind, files, os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'],
                os.environ['GITHUB_REF_NAME'], os.environ['GITHUB_REF_TYPE'], os.environ['GITHUB_RUN_ID'],
                os.environ['GITHUB_TOKEN'], args.tag)
if __name__ == '__main__': main()
