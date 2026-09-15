#!/usr/bin/env python3
"""Build a deterministic, allowlisted Splunk package; never package local/.context."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ("LICENSE", "README.md")
DIRECTORIES = ("default", "metadata", "static", "docs")


def package(destination=None):
    destination = Path(destination or ROOT / ".context/dist/sysmon-splunk-app.tgz")
    destination.parent.mkdir(parents=True, exist_ok=True)
    paths = [ROOT / name for name in FILES]
    paths += [p for directory in DIRECTORIES for p in (ROOT / directory).rglob("*") if p.is_file()]
    with destination.open("wb") as out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as archive:
                for path in sorted(paths):
                    if path.is_symlink():
                        raise ValueError(f"Refusing symlink: {path}")
                    relative = path.relative_to(ROOT)
                    if any(part.startswith(".") for part in relative.parts):
                        continue
                    data = path.read_bytes()
                    info = tarfile.TarInfo("sysmon-splunk-app/" + relative.as_posix())
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))
    return destination


if __name__ == "__main__":
    output = package()
    print(output)
    print("sha256=" + hashlib.sha256(output.read_bytes()).hexdigest())
