#!/usr/bin/env python3
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import urllib.request
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    releases = json.loads((root / 'CORE_PROVENANCE.json').read_text())
    output = Path(sys.argv[1] if len(sys.argv) > 1 else 'cores').resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name, url, expected in releases:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit(f'{name}: checksum mismatch')
        if name == 'xray':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                binary = archive.read('xray')
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                member = next(item for item in archive.getmembers()
                              if item.isfile() and item.name.endswith('/sing-box'))
                with archive.extractfile(member) as source:
                    binary = source.read()
        target = output / name
        target.write_bytes(binary)
        target.chmod(0o755)
        print(f'{name}: verified')
    (output / 'provenance.json').write_text(json.dumps(releases, indent=2) + '\n')


if __name__ == '__main__':
    main()
