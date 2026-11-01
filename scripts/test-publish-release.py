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
        self.temp=tempfile.TemporaryDirectory(prefix='op2p-release-test-');self.addCleanup(self.temp.cleanup)
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
    def test_android_reproducible_and_no_keys(self):
        self.artifacts('client');android=self.incoming/'openp2p-c-android';android.mkdir()
        (android/'openp2p-c-android-debug.apk').write_bytes(b'fixture-apk')
        (android/'openp2p.h').write_text('fixture-header')
        release.prepare('client',self.incoming,self.output)
        first=(self.output/'openp2p-c-android-sdk.zip').read_bytes()
        import os
        os.utime(android/'openp2p.h',(1800000000,1800000000))
        release.prepare('client',self.incoming,self.output)
        self.assertEqual(first,(self.output/'openp2p-c-android-sdk.zip').read_bytes())
        with zipfile.ZipFile(io.BytesIO(first)) as archive:self.assertIn('android/openp2p.h',archive.namelist())
        (android/'server.key').write_text('fixture-not-a-real-key')
        with self.assertRaises(RuntimeError):release.prepare('client',self.incoming,self.output)
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
        with patch.object(release,'GitHub',FakeAPI),patch.object(release.subprocess,'check_output',return_value='project(openp2p_c_gateway VERSION 0.2.0 LANGUAGES C)'),contextlib.redirect_stdout(io.StringIO()):
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
