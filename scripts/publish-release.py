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

KINDS = {
    'gateway': ('c-gateway', 'c/gateway/CMakeLists.txt', [
        'openp2p-c-gateway-debian12-x86_64.tar.gz',
        'openp2p-c-gateway-debian13-x86_64.tar.gz',
        'openp2p-c-gateway-docker-amd64.tar.gz']),
    'client': ('c-client', 'c/client/CMakeLists.txt', [
        'openp2p-c-linux-debian12-x86_64.tar.gz', 'openp2p-c-windows-x86_64.zip',
        'openp2p-c-macos-arm64.tar.gz', 'openp2p-c-macos-x86_64.tar.gz'])
}

def prepare(kind, incoming, output):
    output.mkdir(parents=True, exist_ok=True)
    result = []
    for name in KINDS[kind][2]:
        matches = list(incoming.rglob(name))
        if len(matches) != 1 or matches[0].is_symlink() or matches[0].stat().st_size == 0:
            raise RuntimeError('Expected exactly one nonempty CI artifact: ' + name)
        target = output/name
        shutil.copyfile(matches[0], target)
        result.append(target)
    if kind == 'client':
        android = incoming/'openp2p-c-android'
        if not (android/'openp2p-c-android-debug.apk').is_file():
            raise RuntimeError('Missing Android SDK artifact')
        android_files = sorted(p for p in android.rglob('*') if p.is_file())
        if not android_files or any(p.is_symlink() for p in android.rglob('*')):
            raise RuntimeError('Invalid Android SDK layout')
        target = output/'openp2p-c-android-sdk.zip'
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for file in android_files:
                relative = file.relative_to(android)
                # Runtime data and signing keys must never enter a release.
                if file.suffix.lower() in {'.key', '.jks', '.p12', '.pfx', '.crt', '.pem'} or file.name.endswith('.env'):
                    raise RuntimeError('Unexpected private/runtime material in Android SDK')
                info = zipfile.ZipInfo('android/' + relative.as_posix(), date_time=(1980,1,1,0,0,0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, file.read_bytes())
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
            'Content-Type': content_type, 'User-Agent': 'OpenP2P-release-builder'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=180) as response:
            content = response.read()
            return json.loads(content) if content else None

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
        paths = (['c/gateway/src','c/gateway/web','c/gateway/CMakeLists.txt','c/gateway/scripts/embed-web.py','c/gateway/Dockerfile'] if kind=='gateway' else
                 ['c/client/src','c/client/include','c/client/cmake','c/client/platform','c/client/deps.lock.json','c/client/CMakeLists.txt','c/client/android/app/src/main','c/client/android/jni','c/client/android/app/build.gradle'])
        if subprocess.run(['git','diff','--quiet',sha,tag_sha,'--',*paths]).returncode:
            raise RuntimeError('Tag runtime source differs from the tested build')
    notes = ('C 网关：内嵌 Web 控制台、HTTPS/WSS、NAT 探测及连接协调。包含 Debian 12/13 x86_64 原生包和 amd64 Docker 镜像。' if kind == 'gateway' else
             'C 客户端：桌面 CLI / ABI 1 C 库、Android 应用、SOCKS5 TCP/UDP、TCP 打洞与 QUIC。包含 Linux Debian 12、Windows、macOS 两种架构和 Android SDK。')
    body = notes + '\n\n构建提交：`' + sha + '`\n\n[GitHub 构建与测试](https://github.com/' + repository + '/actions/runs/' + run_id + ')\n\n下载后使用 `SHA256SUMS.txt` 校验。运行配置、账号、证书和私钥不在发行包中。'
    metadata = {'tag_name': tag, 'target_commitish': sha,
                'name': ('C Gateway ' if kind == 'gateway' else 'C Client ') + version + ('' if stable else ' · development ' + run_id),
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
    release = api.request('/releases/' + str(release['id']),
                          {'draft': False, 'prerelease': not stable, 'make_latest': 'true' if stable else 'false'}, method='PATCH')
    print('Published:', release['html_url'])

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kind', choices=KINDS, required=True)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-only', action='store_true')
    p.add_argument('--tag')
    args = p.parse_args()
    files = prepare(args.kind, args.input, args.output)
    if not args.prepare_only:
        publish(args.kind, files, os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'],
                os.environ['GITHUB_REF_NAME'], os.environ['GITHUB_REF_TYPE'], os.environ['GITHUB_RUN_ID'],
                os.environ['GITHUB_TOKEN'], args.tag)
if __name__ == '__main__': main()
