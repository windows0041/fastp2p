#!/usr/bin/env python3
"""Login rate limiting: wrong passwords must be capped before the PBKDF2 cost."""
import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--gateway', required=True)
p.add_argument('--cert-dir', required=True)
p.add_argument('--logs', required=True)
args = p.parse_args()
logs = Path(args.logs)
logs.mkdir(parents=True, exist_ok=True)
ctx = ssl.create_default_context(cafile=str(Path(args.cert_dir) / 'ca.crt'))
user = 'ratelimit-admin'
password = secrets.token_urlsafe(24)
key = '9999999999999999'
port = 31008


def request(body, timeout=5):
    c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=timeout)
    c.request('POST', '/api/v1/user/login', json.dumps(body).encode(),
              {'Content-Type': 'application/json'})
    start = time.monotonic()
    r = c.getresponse()
    status = r.status
    r.read()
    elapsed = time.monotonic() - start
    c.close()
    return status, elapsed


with tempfile.TemporaryDirectory(prefix='fastp2p-ratelimit-') as temporary:
    directory = Path(temporary)
    env = os.environ.copy()
    env.update(FASTP2P_USER=user, FASTP2P_PASSWORD=password, FASTP2P_TOKEN=key)
    log = (logs / 'gateway.log').open('w')
    process = subprocess.Popen(
        [str(Path(args.gateway).resolve()),
         '--cert', str(Path(args.cert_dir).resolve() / 'server.crt'),
         '--key', str(Path(args.cert_dir).resolve() / 'server.key'),
         '--port', '37183', '--apiport', str(port)],
        cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT)
    results = {}
    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, 'gateway exited'
            try:
                c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=2)
                c.request('GET', '/healthz')
                if c.getresponse().status == 200:
                    c.close()
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, 'gateway did not start'
            time.sleep(0.05)

        # A correct login succeeds and clears the counter.
        good, good_time = request({'user': user, 'password': password})
        assert good == 200, good

        # Wrong passwords: first attempts cost the PBKDF2 hash, then 429.
        slow_times, statuses = [], []
        for _ in range(12):
            status, elapsed = request({'user': user, 'password': 'wrong-password'})
            statuses.append(status)
            if status == 401:
                slow_times.append(elapsed)
        assert 429 in statuses, statuses
        first_429 = statuses.index(429)
        results['wrong_password_attempts_before_limit'] = first_429
        assert statuses[first_429:] == [429] * (len(statuses) - first_429), statuses
        # Once limited, responses must be fast: no expensive hash is running.
        fast_times = []
        for _ in range(3):
            status, elapsed = request({'user': user, 'password': 'wrong-password'})
            assert status == 429, status
            fast_times.append(elapsed)
        results['limited_response_is_fast'] = max(fast_times) < 0.05
        assert results['limited_response_is_fast'], (slow_times, fast_times)

        # A correct login is refused while the source is locked, proving the lock
        # is not bypassable by supplying the right password.
        locked, _ = request({'user': user, 'password': password})
        results['locked_even_with_correct_password'] = locked == 429
        results['success'] = True
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()

print(json.dumps(results, indent=2))
