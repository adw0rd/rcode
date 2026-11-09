"""Opt-in TODO API controls; no model API and no project execution on host."""
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'evals'),str(ROOT/'evals/runtime')]
import eval_controls
from host_docker import Docker,Failure
from runtime import strict

class TodoOracleContractTests(unittest.TestCase):
    def test_embedded_script_matches_oracle_file(self):
        script=(ROOT/'evals/todo-api/oracles/check_api.py').read_text()
        oracle=strict((ROOT/'evals/todo-api/oracles/todo-api.json').read_bytes())
        self.assertEqual(oracle,{'version':1,'prepare':[],'checks':[{
            'id':'http-crud-contract','argv':['python3','-I','-c',script],
            'stdin':'','timeout_secs':60,'expected_exit':0,'expected_json':{'status':'ok'}}]})

@unittest.skipUnless(os.environ.get('RCODE_EVAL_IMAGE') and os.environ.get('RCODE_EVAL_SOCKET'),'opt-in Docker controls: set RCODE_EVAL_IMAGE and RCODE_EVAL_SOCKET')
class TodoApiControls(eval_controls.CorpusControls):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='rcode-eval-todo-controls-');cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name);config=cls.root/'docker';config.mkdir(mode=0o700)
        cls.fixtures=eval_controls.Fixtures();cls.addClassCleanup(os.close,cls.fixtures.fd)
        image=os.environ['RCODE_EVAL_IMAGE'];socket=os.environ['RCODE_EVAL_SOCKET']
        executable=os.environ.get('RCODE_EVAL_DOCKER') or shutil.which('docker')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not executable or not Path(executable).is_absolute() or not Path(socket).is_absolute():raise ValueError('explicit local Docker configuration required')
        cls.docker=Docker(executable,socket,config,image,ROOT/'evals/runtime');cls.addClassCleanup(lambda:cls.docker.cleanup(time.monotonic()+15))

    def test_negative_and_corrected_controls(self):
        oracle=strict(self.fixtures.read('todo-api/oracles/todo-api.json')[0])
        check=oracle['checks'][0]
        script=self.fixtures.read('todo-api/oracles/check_api.py')[0].decode()
        self.assertEqual(check['argv'][3],script)
        if self.docker.active or self.docker.volumes:raise Failure('previous cleanup unknown; TODO control stopped')
        negative=self.root/'todo-api-negative';positive=self.root/'todo-api-corrected'
        self.fixtures.stage('todo-api/cases/todo-api/project',negative)
        rejected=not self.observe(negative,oracle,check)
        self.assertTrue(rejected,'unchanged source passed the hidden HTTP check')
        self.assertTrue((ROOT/'evals/controls/todo-api').is_dir(),'positive control is missing')
        self.fixtures.stage('controls/todo-api',positive)
        self.assertTrue(self.observe(positive,oracle,check),'corrected control failed: http-crud-contract')
        print('todo-api: negative rejected, corrected passed',flush=True)
        print('1/1 functional controls; no model inference performed',flush=True)

if __name__=='__main__':unittest.main()
