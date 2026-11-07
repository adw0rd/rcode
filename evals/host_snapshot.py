"""Safely materialize a paused-container Docker-cp archive on the host."""
from __future__ import annotations

import hashlib
import io
import os
import tarfile
from pathlib import Path

_MAX_ARCHIVE = 80 * 1024 * 1024
_MAX_FILE = 2 * 1024 * 1024
_MAX_TOTAL = 64 * 1024 * 1024
_MAX_ENTRIES = 10_000
_MAX_DEPTH = 32


def extract_frozen(data: bytes, destination: Path) -> str:
    try:
        return _extract_frozen(data, destination)
    except (tarfile.TarError, RecursionError):
        raise ValueError("invalid or excessively complex tar archive") from None


def _extract_frozen(data: bytes, destination: Path) -> str:
    """Extract only ``workspace/...`` entries and return a deterministic SHA-256.

    The sole accepted archive root convention is ``workspace/``; a ``.`` root
    is deliberately rejected. The destination must already exist and be empty.
    On failure, any files already written remain for the caller to clean up.
    """
    if len(data) > _MAX_ARCHIVE:
        raise ValueError("archive exceeds 80 MiB")
    rootfd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.listdir(rootfd):
            raise ValueError("destination must be empty")
        os.fchmod(rootfd, 0o700)
        explicit = set()
        nodes: dict[str, tuple[str, bool, bytes | None]] = {}
        total = 0
        members = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                members += 1
                if members > _MAX_ENTRIES + 1: raise ValueError("too many archive entries")
                name = member.name
                if len(name.encode("utf-8")) > 1024: raise ValueError("archive path length")
                if "\x00" in name or "\\" in name or name.startswith("/"):
                    raise ValueError("unsafe archive path")
                if name == "workspace" and member.isdir():
                    rel = ""
                else:
                    if not name.startswith("workspace/"):
                        raise ValueError("archive entries must be under workspace/")
                    rel = name[len("workspace/"):]
                    if member.isdir() and rel.endswith("/"):
                        rel = rel[:-1]
                    if not rel:
                        if member.isdir():
                            continue
                        raise ValueError("invalid workspace root entry")
                parts = rel.split("/") if rel else []
                if any(p in ("", ".", "..") for p in parts) or len(parts) > _MAX_DEPTH:
                    raise ValueError("unsafe path components or excessive depth")
                if member.type == tarfile.GNUTYPE_SPARSE or getattr(member, "sparse", None) or any(k.startswith("GNU.sparse") for k in member.pax_headers):
                    raise ValueError("sparse entries are not accepted")
                if member.isdir():
                    kind, executable, content = "dir", False, None
                elif member.isreg():
                    if member.size < 0 or member.size > _MAX_FILE:
                        raise ValueError("regular file exceeds 2 MiB")
                    total += member.size
                    if total > _MAX_TOTAL:
                        raise ValueError("regular files exceed 64 MiB aggregate")
                    executable = bool(member.mode & 0o111)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError("missing regular file data")
                    chunks = []
                    remaining = member.size
                    while remaining:
                        chunk = stream.read(min(65536, remaining))
                        if not chunk:
                            raise ValueError("truncated regular file")
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    content = b"".join(chunks)
                    if stream.read(1):
                        raise ValueError("regular file exceeds declared size")
                    kind = "file"
                else:
                    raise ValueError("links and special entries are not accepted")
                if not rel:
                    continue
                if rel in explicit:
                    raise ValueError("duplicate archive path")
                explicit.add(rel)
                for i in range(1, len(parts)):
                    parent = "/".join(parts[:i])
                    if parent in nodes and nodes[parent][0] != "dir":
                        raise ValueError("file used as a parent directory")
                if kind == "file" and rel in nodes:
                    raise ValueError("file conflicts with an existing directory")
                for i in range(1, len(parts)):
                    nodes.setdefault("/".join(parts[:i]), ("dir", False, None))
                nodes[rel] = (kind, executable, content)
                if len(nodes) > _MAX_ENTRIES:
                    raise ValueError("too many tree entries")
                # Materialize missing parents descriptor-relatively, never following links.
                parentfd = os.dup(rootfd)
                try:
                    for part in parts[:-1]:
                        try:
                            os.mkdir(part, 0o700, dir_fd=parentfd)
                        except FileExistsError:
                            pass
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                        os.close(parentfd)
                        parentfd = child
                    leaf = parts[-1]
                    if kind == "dir":
                        try:
                            os.mkdir(leaf, 0o700, dir_fd=parentfd)
                        except FileExistsError:
                            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                            os.close(fd)
                    else:
                        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parentfd)
                        try:
                            view = memoryview(content or b"")
                            while view:
                                written = os.write(fd, view)
                                if written <= 0:
                                    raise OSError("short write")
                                view = view[written:]
                            os.fchmod(fd, 0o555 if executable else 0o444)
                        finally:
                            os.close(fd)
                finally:
                    os.close(parentfd)
        # Include explicit and implicit directories in the digest and entry limit.
        for path in list(nodes):
            parts = path.split("/")
            for i in range(1, len(parts)):
                parent = "/".join(parts[:i])
                if parent not in nodes:
                    nodes[parent] = ("dir", False, None)
        if len(nodes) > _MAX_ENTRIES:
            raise ValueError("too many tree entries")
        digest = hashlib.sha256()
        for path in sorted(nodes):
            kind, executable, content = nodes[path]
            p = path.encode("utf-8")
            body = content or b""
            # Length-prefixed path and payload avoid ambiguous concatenations.
            digest.update(b"D" if kind == "dir" else (b"X" if executable else b"F"))
            digest.update(len(p).to_bytes(4, "big")); digest.update(p)
            digest.update(len(body).to_bytes(8, "big")); digest.update(body)
        for path in sorted((k for k,v in nodes.items() if v[0] == "dir"), key=lambda p:p.count("/"), reverse=True):
            os.chmod(destination / path, 0o555)
        os.fchmod(rootfd, 0o555)
        return digest.hexdigest()
    finally:
        os.close(rootfd)


if __name__ == "__main__":
    import unittest
    import tempfile

    class ExtractFrozenTests(unittest.TestCase):
        def archive(self, entries):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w") as tf:
                for name, kind, payload in entries:
                    ti = tarfile.TarInfo(name)
                    ti.type = kind
                    if kind == tarfile.REGTYPE:
                        ti.size = len(payload)
                        tf.addfile(ti, io.BytesIO(payload))
                    else:
                        tf.addfile(ti)
            return out.getvalue()

        def run_extract(self, data):
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "out"
                dest.mkdir(mode=0o700)
                return extract_frozen(data, dest), dest

        def test_valid_workspace_root(self):
            data = self.archive([("workspace/", tarfile.DIRTYPE, b""),
                                 ("workspace/a", tarfile.REGTYPE, b"ok")])
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "out"; dest.mkdir()
                first = extract_frozen(data, dest)
                self.assertEqual((dest / "a").read_bytes(), b"ok")
                self.assertEqual(len(first), 64)

        def test_rejects_traversal_duplicate_and_links(self):
            bad = [self.archive([("workspace/../x", tarfile.REGTYPE, b"x")]),
                   self.archive([("workspace/a", tarfile.REGTYPE, b"x"),
                                 ("workspace/a", tarfile.REGTYPE, b"x")]),
                   self.archive([("workspace/l", tarfile.SYMTYPE, b"")]),
                   self.archive([("workspace/l", tarfile.LNKTYPE, b"")])]
            for data in bad:
                with self.subTest(data=data[:20]), self.assertRaises((ValueError, tarfile.TarError)):
                    with tempfile.TemporaryDirectory() as tmp:
                        dest = Path(tmp) / "out"; dest.mkdir()
                        extract_frozen(data, dest)

        def test_rejects_special_and_oversized_files(self):
            for data in (self.archive([("workspace/f", tarfile.FIFOTYPE, b"")]),
                         self.archive([("workspace/f", tarfile.REGTYPE, b"x" * (_MAX_FILE + 1))])):
                with self.assertRaises((ValueError, tarfile.TarError)):
                    with tempfile.TemporaryDirectory() as tmp:
                        dest = Path(tmp) / "out"; dest.mkdir()
                        extract_frozen(data, dest)

    unittest.main()
