"""The accelerator must never replace GitHub's integrity checks."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location(
    'release_sync', Path(__file__).resolve().parents[1] / 'deploy/fastp2p-sync-releases.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class ReleaseDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'package'
        self.payload = b'verified public package'
        self.sha = hashlib.sha256(self.payload).hexdigest()
        self.repository = 'windows0041/fastp2p'
        self.release = {'tag_name': 'fastp2p-client-v2.0.2'}
        self.url = 'https://github.com/windows0041/fastp2p/releases/download/fastp2p-client-v2.0.2/file.exe'
        self.asset = {
            'name': 'file.exe', 'id': 1, 'state': 'uploaded', 'size': len(self.payload),
            'url': 'https://api.github.com/repos/windows0041/fastp2p/releases/assets/1',
            'browser_download_url': self.url, 'digest': 'sha256:' + self.sha,
        }

    def download(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return sync.download(self.repository, self.release, self.asset, self.path,
                                 download_prefix='https://gh-proxy.com/')

    def test_verified_accelerated_file(self):
        with patch.object(sync, 'fetch', return_value=io.BytesIO(self.payload)) as fetch:
            self.assertEqual(self.download(), self.sha)
        self.assertEqual(fetch.call_args.args, ('https://gh-proxy.com/' + self.url, 'application/octet-stream', True))
        self.assertEqual(self.path.read_bytes(), self.payload)

    def test_corrupt_accelerator_falls_back_and_discards_partial_file(self):
        with patch.object(sync, 'fetch', side_effect=[io.BytesIO(b'x' * len(self.payload)), io.BytesIO(self.payload)]) as fetch:
            self.assertEqual(self.download(), self.sha)
        self.assertTrue(fetch.call_args_list[0].args[2])
        self.assertFalse(fetch.call_args_list[1].args[2])
        self.assertTrue(fetch.call_args_list[1].args[0].startswith(self.asset['url']))
        self.assertEqual(self.path.read_bytes(), self.payload)

    def test_failed_accelerator_and_failed_official_download_leave_no_file(self):
        with patch.object(sync, 'fetch', side_effect=[urllib.error.URLError('unavailable'), io.BytesIO(b'bad')]):
            with self.assertRaisesRegex(ValueError, 'size or SHA-256'):
                self.download()
        self.assertFalse(self.path.exists())

    def test_checksum_without_github_digest_uses_official_endpoint(self):
        self.asset['digest'] = None
        with patch.object(sync, 'fetch', return_value=io.BytesIO(self.payload)) as fetch:
            self.assertEqual(self.download(), self.sha)
        self.assertEqual(fetch.call_count, 1)
        self.assertFalse(fetch.call_args.args[2])

    def test_prefix_and_redirect_boundaries(self):
        for prefix in ('http://gh-proxy.com/', 'https://evil.invalid/', 'https://user@gh-proxy.com/',
                       'https://gh-proxy.com:8443/', 'https://gh-proxy.com/path/', 'https://gh-proxy.com/?key=1'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                sync.validate_download_prefix(prefix)
        self.assertEqual(sync.validate_download_prefix('https://gh-proxy.com'), 'https://gh-proxy.com/')
        request = urllib.request.Request(self.asset['url'])
        for handler, url in ((sync.GitHubRedirect(), 'https://gh-proxy.com/file'),
                             (sync.GitHubRedirect(True), 'http://gh-proxy.com/file'),
                             (sync.GitHubRedirect(True), 'https://evil.invalid/file'),
                             (sync.GitHubRedirect(True), 'https://gh-proxy.com:8443/file')):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, '', {}, url)

    def test_latest_release_lookup_uses_configured_accelerator(self):
        payload = json.dumps([
            {'tag_name': 'fastp2p-client-v2.0.2', 'draft': False, 'prerelease': False},
            {'tag_name': 'fastp2p-gateway-v9.0.0', 'draft': False, 'prerelease': False},
            {'tag_name': 'fastp2p-client-v3.0.0', 'draft': False, 'prerelease': True},
        ]).encode()
        with patch.object(sync, 'fetch', return_value=io.BytesIO(payload)) as fetch:
            version, _ = sync.latest(self.repository, 'https://gh-proxy.com/')
        self.assertEqual(version, '2.0.2')
        self.assertTrue(fetch.call_args.args[0].startswith('https://gh-proxy.com/https://api.github.com/'))
        self.assertTrue(fetch.call_args.kwargs['accelerated'])

    def test_failed_accelerated_metadata_falls_back_to_direct_api(self):
        with patch.object(sync, 'fetch', side_effect=[urllib.error.URLError('unavailable'), io.BytesIO(b'[]')]) as fetch:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(sync.release_page('https://api.github.com/fixture', 'https://gh-proxy.com/'), [])
        self.assertEqual(fetch.call_args.args, ('https://api.github.com/fixture',))
        self.assertFalse(fetch.call_args.kwargs['accelerated'])


if __name__ == '__main__':
    unittest.main()
