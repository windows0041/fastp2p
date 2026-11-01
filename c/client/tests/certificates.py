"""Portable, test-only private CA generator; no shell or global trust changes."""
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess

def create_certificates(directory, hostname):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    executable = os.environ.get('OPENSSL_EXE') or shutil.which('openssl')
    if not executable and os.name == 'nt':
        executable = r'C:\Program Files\Git\usr\bin\openssl.exe'
    if not executable:
        raise RuntimeError('Install OpenSSL or set OPENSSL_EXE')
    def run(*arguments):
        subprocess.run([executable, *arguments], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-sha256', '-subj', '/CN=OpenP2P Test CA',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-addext', 'subjectKeyIdentifier=hash', '-addext', 'authorityKeyIdentifier=keyid:always')
    run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
        '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=OpenP2P Test Gateway')
    try:
        san = 'IP:' + str(ipaddress.ip_address(hostname))
    except ValueError:
        san = 'DNS:' + hostname
    (directory/'server.ext').write_text('subjectAltName='+san+'\nbasicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
        'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    run('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
        '-out', 'server.crt', '-days', '1', '-sha256', '-extfile', 'server.ext')
    verified=subprocess.run([executable,'verify','-x509_strict','-CAfile','ca.crt','server.crt'],
        cwd=directory,capture_output=True,text=True)
    if verified.returncode:
        raise RuntimeError('Invalid test certificate chain: '+verified.stdout+verified.stderr)
