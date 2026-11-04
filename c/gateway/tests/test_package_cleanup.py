"""Cache cleanup must preserve usable releases, leases and unrelated files."""
from contextlib import closing
import hashlib,importlib.util,io,sqlite3,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('sync',Path(__file__).resolve().parents[1]/'deploy/fastp2p-sync-releases.py')
sync=importlib.util.module_from_spec(spec);spec.loader.exec_module(sync)

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.directory=self.root/'updates';self.directory.mkdir()
        self.database=self.root/'nodes.sqlite3'
        with closing(sqlite3.connect(self.database)) as db,db:
            for table in ('updates','release_packages'):
                db.execute(f'CREATE TABLE {table}(platform TEXT,version TEXT,sha256 TEXT,size INTEGER,filename TEXT,uploaded_at INTEGER,PRIMARY KEY(platform,version))')
            db.execute('CREATE TABLE release_sync(id INTEGER PRIMARY KEY,version TEXT,release_id INTEGER)')
            db.execute("INSERT INTO release_sync VALUES(1,'2.0.3',3)")
        self.latest=self.seed('release_packages','2.0.3')

    def seed(self,table,version,platform='windows',payload=None):
        payload=payload or (table+platform+version).encode()
        sha=hashlib.sha256(payload).hexdigest()
        name=('github-' if table=='release_packages' else '')+platform+'-'+version+'-'+sha
        path=self.directory/name;path.write_bytes(payload)
        with closing(sqlite3.connect(self.database)) as db,db:
            db.execute(f'INSERT INTO {table} VALUES(?,?,?,?,?,?)',(platform,version,sha,len(payload),name,0))
        return path

    def rows(self,table):
        with closing(sqlite3.connect(self.database)) as db:
            return db.execute(f'SELECT platform,version FROM {table}').fetchall()

    def test_removes_old_mirrors_and_manual_packages_but_keeps_equal_and_newer(self):
        old=self.seed('release_packages','2.0.2')
        manual=self.seed('updates','2.0.1')
        equal=self.seed('updates','2.0.3.0')
        newer=self.seed('updates','2.0.10')
        result=sync.cleanup(self.database,now=1000)
        self.assertEqual(result['records'],2)
        self.assertFalse(old.exists());self.assertFalse(manual.exists())
        self.assertTrue(all(p.exists() for p in (self.latest,equal,newer)))
        self.assertEqual(set(self.rows('updates')),{('windows','2.0.3.0'),('windows','2.0.10')})

    def test_lease_preserves_queued_upgrade_and_installer_until_expiration(self):
        old=self.seed('release_packages','2.0.2')
        manual=self.seed('updates','2.0.2')
        sha=old.name.rsplit('-',1)[1]
        installer=self.directory/('installer-'+'a'*64+'-'+sha+'.sh');installer.write_bytes(b'installer')
        sync.cleanup(self.database,now=1000)
        # Recreate a pending request against the older version.
        old=self.seed('release_packages','2.0.2');manual=self.seed('updates','2.0.2')
        installer.write_bytes(b'installer')
        with closing(sqlite3.connect(self.database)) as db,db:
            db.execute("INSERT INTO package_leases VALUES('windows','2.0.2',1600)")
        result=sync.cleanup(self.database,now=1599)
        self.assertEqual(result['deferred'],2)
        self.assertTrue(all(p.exists() for p in (old,manual,installer)))
        sync.cleanup(self.database,now=1601)
        self.assertFalse(any(p.exists() for p in (old,manual,installer)))
        self.assertTrue(self.latest.exists())

    def test_unlink_does_not_interrupt_an_open_download(self):
        old=self.seed('updates','2.0.1',payload=b'open download bytes')
        with old.open('rb') as stream:
            sync.cleanup(self.database,now=1000)
            self.assertFalse(old.exists())
            self.assertEqual(stream.read(),b'open download bytes')

    def test_corrupt_filename_and_symlink_never_delete_outside_the_cache(self):
        outside=self.root/'outside';outside.write_bytes(b'keep')
        old=self.seed('updates','2.0.1');old.unlink();old.symlink_to(outside)
        with closing(sqlite3.connect(self.database)) as db,db:
            db.execute("INSERT INTO updates VALUES('android','1.0.0',?,4,'../outside',0)",('a'*64,))
        unrelated=self.directory/'notes.txt';unrelated.write_bytes(b'keep too')
        sync.cleanup(self.database,now=1000)
        self.assertEqual(outside.read_bytes(),b'keep');self.assertEqual(unrelated.read_bytes(),b'keep too')
        self.assertFalse(old.is_symlink())

    def test_failed_unlink_is_retried_by_a_later_cleanup(self):
        old=self.seed('updates','2.0.1');original=Path.unlink
        def denied(path,*args,**kwargs):
            if path==old:raise PermissionError('temporary test denial')
            return original(path,*args,**kwargs)
        with patch.object(Path,'unlink',denied):
            self.assertEqual(sync.cleanup(self.database,now=1000)['deferred'],1)
        self.assertTrue(old.exists());self.assertEqual(self.rows('updates'),[])
        self.assertEqual(sync.cleanup(self.database,now=1001)['files'],1)
        self.assertFalse(old.exists());self.assertTrue(self.latest.exists())

    def test_failed_release_import_does_not_run_cleanup(self):
        old=self.seed('updates','2.0.1')
        with patch.object(sync,'import_release',side_effect=ValueError('bad package')),patch.object(sync,'cleanup') as cleanup:
            with self.assertRaises(ValueError):sync.sync(self.database,'windows0041/fastp2p')
        cleanup.assert_not_called();self.assertTrue(old.exists());self.assertTrue(self.latest.exists())

    def release_fixture(self, corrupt=False):
        """Real checksums/extraction/SQLite publication, only HTTP transport stubbed."""
        repository='windows0041/fastp2p'; tag='fastp2p-client-v2.0.4'
        names=['fastp2p-windows-x86_64.exe','fastp2p-android.apk','fastp2p-linux-static-x86_64.tar.gz',
               'fastp2p-macos-arm64.tar.gz','fastp2p-macos-x86_64.tar.gz']
        payloads={}
        for name in names:
            member=sync.ASSETS[name][1]; data=('package '+name).encode()
            if member:
                buffer=io.BytesIO()
                with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
                    info=tarfile.TarInfo(member);info.size=len(data);archive.addfile(info,io.BytesIO(data))
                data=buffer.getvalue()
            payloads[name]=data
        payloads['SHA256SUMS.txt']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'
            for name,data in payloads.items()).encode()
        assets=[]
        for index,(name,data) in enumerate(payloads.items(),1):
            assets.append({'name':name,'id':index,'state':'uploaded','size':len(data),
                'browser_download_url':f'https://github.com/{repository}/releases/download/{tag}/{name}',
                'url':f'https://api.github.com/repos/{repository}/releases/assets/{index}',
                'digest':'sha256:'+hashlib.sha256(data).hexdigest()})
        def fetch(url,*args,**kwargs):
            index=int(url.split('/assets/')[1].split('?')[0])-1
            data=payloads[assets[index]['name']]
            if corrupt and index==1:data=b'x'*len(data)
            return io.BytesIO(data)
        return {'id':4,'tag_name':tag,'assets':assets},fetch

    def test_real_sync_commits_complete_batch_then_prunes_also_on_cached_fastpath(self):
        old=self.seed('updates','2.0.1');release,fetch=self.release_fixture()
        with patch.object(sync,'latest',return_value=('2.0.4',release)),patch.object(sync,'fetch',side_effect=fetch):
            self.assertEqual(sync.sync(self.database,'windows0041/fastp2p'),'2.0.4')
        self.assertFalse(old.exists());self.assertFalse(self.latest.exists())
        self.assertEqual(len(self.rows('release_packages')),5)
        old=self.seed('updates','2.0.2')
        with patch.object(sync,'latest',return_value=('2.0.4',release)),patch.object(sync,'fetch') as fetch:
            sync.sync(self.database,'windows0041/fastp2p')
        fetch.assert_not_called();self.assertFalse(old.exists())

    def test_real_checksum_failure_keeps_old_rows_and_files(self):
        old=self.seed('updates','2.0.1');release,fetch=self.release_fixture(corrupt=True)
        with patch.object(sync,'latest',return_value=('2.0.4',release)),patch.object(sync,'fetch',side_effect=fetch):
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                sync.sync(self.database,'windows0041/fastp2p')
        self.assertTrue(old.exists());self.assertTrue(self.latest.exists())
        self.assertEqual(self.rows('release_packages'),[('windows','2.0.3')])

if __name__=='__main__':unittest.main()
