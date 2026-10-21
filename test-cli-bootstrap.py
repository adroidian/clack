#!/usr/bin/env python3
"""test-cli-bootstrap.py -- GAP 1 regression: relay-cli.py must be a single
runnable file. /join/client serves ONLY relay-cli.py; a downloaded client in
an empty directory must work without e2ee.py or any other sibling file.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_CLI = os.path.join(HERE, "relay-cli.py")
E2EE_SRC = os.path.join(HERE, "e2ee.py")

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS " + name)
    else:
        FAIL += 1
        print("FAIL " + name + (" -- " + str(detail) if detail else ""))


tmpd = tempfile.mkdtemp(prefix="cli-bootstrap-")
try:
    # Only relay-cli.py in the directory -- no e2ee.py, no ed25519.py, nothing.
    shutil.copy(RELAY_CLI, os.path.join(tmpd, "relay-cli.py"))
    files = os.listdir(tmpd)
    check("isolated dir has only relay-cli.py", files == ["relay-cli.py"], files)

    r = subprocess.run([sys.executable, "relay-cli.py", "--help"],
                       capture_output=True, text=True, cwd=tmpd, timeout=30)
    check("--help exits 0 in isolation", r.returncode == 0, r.stderr[:200])

    # The e2ee namespace must be functional (not just importable).
    r = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util; "
         "s=importlib.util.spec_from_file_location('rc','relay-cli.py'); "
         "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
         "assert hasattr(m.e2ee,'encrypt_envelope'); "
         "assert hasattr(m.e2ee,'decrypt_envelope'); "
         "print('e2ee ok')"],
        capture_output=True, text=True, cwd=tmpd, timeout=30)
    check("e2ee namespace functional in isolation",
          r.returncode == 0 and "e2ee ok" in r.stdout, r.stderr[:200])

    # Embedded source must match the canonical e2ee.py (drift check).
    r = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util; "
         "s=importlib.util.spec_from_file_location('rc','relay-cli.py'); "
         "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
         "src=open(r'%s').read().split(chr(10)); "
         "src=src[1:] if src[0].startswith('#!') else src; "
         "assert m._E2EE_SOURCE == chr(10).join(src), 'drift'; "
         "print('in sync')" % E2EE_SRC],
        capture_output=True, text=True, cwd=tmpd, timeout=30)
    check("embedded e2ee matches canonical e2ee.py",
          r.returncode == 0 and "in sync" in r.stdout, r.stderr[:200])
finally:
    shutil.rmtree(tmpd, ignore_errors=True)

print("----")
print("pass=%d fail=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
