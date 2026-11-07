"""Pure data boundary tests, without project imports or model requests."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'evals'),str(ROOT/'evals/runtime')]
from runtime import strict
from host_snapshot import extract_frozen

class Boundaries(unittest.TestCase):
    def test_deep_json_is_a_validation_error(self):
        with self.assertRaises(ValueError):strict(b'['*2000+b'0'+b']'*2000)
    def test_invalid_tar_is_a_validation_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_frozen(b'not a tar archive',Path(tmp))
    def test_archive_cannot_create_implicit_directories_beyond_entry_quota(self):
        import host_snapshot
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tf:
            info=tarfile.TarInfo('workspace/a/b/c/d/value');info.size=1;tf.addfile(info,io.BytesIO(b'x'))
        original=host_snapshot._MAX_ENTRIES
        try:
            host_snapshot._MAX_ENTRIES=3
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):extract_frozen(stream.getvalue(),Path(tmp))
                self.assertFalse((Path(tmp)/'a').exists())
        finally:host_snapshot._MAX_ENTRIES=original
if __name__=='__main__':unittest.main()
