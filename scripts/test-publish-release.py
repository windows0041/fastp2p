#!/usr/bin/env python3
"""Check artifact completeness, reproducible Android packaging and draft publication."""
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
import zipfile

spec=importlib.util.spec_from_file_location('release',Path(__file__).with_name('publish-release.py'))
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fastp2p-release-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        assert self.root.resolve().parent==Path(tempfile.gettempdir()).resolve()
        self.incoming=self.root/'incoming';self.incoming.mkdir();self.output=self.root/'output'
    def artifacts(self,kind):
        for name in release.KINDS[kind][2]:
            (self.incoming/name).write_bytes(('fixture:'+name).encode())
    def test_missing_and_duplicate_artifacts(self):
        self.artifacts('gateway')
        file=self.incoming/release.KINDS['gateway'][2][0]
        duplicate=self.incoming/'duplicate';duplicate.mkdir();(duplicate/file.name).write_bytes(file.read_bytes())
        with self.assertRaises(RuntimeError):release.prepare('gateway',self.incoming,self.output)
        (duplicate/file.name).unlink();file.unlink()
        with self.assertRaises(RuntimeError):release.prepare('gateway',self.incoming,self.output)
    def test_checksums(self):
        self.artifacts('gateway');files=release.prepare('gateway',self.incoming,self.output)
        for line in files[-1].read_text().splitlines():
            digest,name=line.split('  ',1)
            self.assertEqual(digest,hashlib.sha256((self.output/name).read_bytes()).hexdigest())
    def test_direct_client_artifacts(self):
        self.artifacts('client')
        files=release.prepare('client',self.incoming,self.output)
        self.assertIn('fastp2p-android.apk',{p.name for p in files})
        self.assertIn('fastp2p-windows-x86_64.exe',{p.name for p in files})
        self.assertIn('fastp2p-linux-x86_64',{p.name for p in files})
        (self.incoming/'private.key').write_text('fixture')
        self.assertNotIn('private.key',{p.name for p in release.prepare('client',self.incoming,self.output)})
    def test_artifact_directory_can_share_binary_name(self):
        for name in release.KINDS['client'][2]:
            directory=self.incoming/name;directory.mkdir()
            (directory/name).write_bytes(b'fixture')
        self.assertEqual(len(release.prepare('client',self.incoming,self.output)),10)
    def publication(self,bad_digest=False):
        self.artifacts('gateway');files=release.prepare('gateway',self.incoming,self.output);calls=[]
        class FakeAPI:
            def __init__(self,*args):pass
            def request(self,path,data=None,method='GET',content_type=None):
                calls.append((path,method,data if isinstance(data,dict) else None))
                if path.startswith('/releases/tags/'):
                    raise urllib.error.HTTPError('fixture',404,'not found',{},None)
                if path=='/releases' and method=='POST':
                    assert data['draft'] is True
                    return {'id':1,'draft':True,'assets':[],'upload_url':'https://uploads.github.com/repos/test/repo/releases/1/assets{?name}'}
                if method=='POST':return {'id':2,'size':len(data),'digest':'sha256:'+('invalid' if bad_digest else hashlib.sha256(data).hexdigest())}
                if method=='PATCH':return {'html_url':'https://github.com/test/repo/releases/tag/fixture'}
                raise AssertionError((path,method))
        with patch.object(release,'GitHub',FakeAPI),patch.object(release.subprocess,'check_output',return_value='project(fastp2p_c_gateway VERSION 0.2.0 LANGUAGES C)'),contextlib.redirect_stdout(io.StringIO()):
            if bad_digest:
                with self.assertRaises(RuntimeError):release.publish('gateway',files,'test/repo','a'*40,'main','branch','123','fixture-token')
            else:release.publish('gateway',files,'test/repo','a'*40,'main','branch','123','fixture-token')
        return calls
    def test_draft_until_all_assets_verified(self):
        calls=self.publication()
        self.assertEqual(sum(m=='POST' and p.startswith('https://uploads.') for p,m,d in calls),4)
        self.assertEqual(calls[-1][1],'PATCH');self.assertFalse(calls[-1][2]['draft'])
    def test_upload_mismatch_never_publishes(self):
        calls=self.publication(True)
        self.assertFalse(any(method=='PATCH' for path,method,data in calls))

if __name__=='__main__':unittest.main()
