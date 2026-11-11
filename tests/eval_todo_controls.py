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

    def test_task_documents_observable_http_contract(self):
        task=(ROOT/'evals/todo-api/cases/todo-api/task.md').read_text()
        required=(
            '- `GET /health` возвращает ровно статус 200 и JSON `{"status":"ok"}` без дополнительных полей.',
            '- `POST /todos` возвращает 201, `GET /todos`, `GET /todos/{id}` и `PATCH /todos/{id}` возвращают 200, `DELETE /todos/{id}` возвращает 204 без тела.',
            '- Объект TODO содержит ровно поля `id`, `title`, `completed`, без дополнительных полей. ID — последовательные положительные целые, начиная с 1; удалённые ID не переиспользуются. `GET /todos` сохраняет порядок создания.',
            '- Отсутствие ключа `title` в теле POST отклоняй со статусом 422.',
            '- Строковый `title` с длиной после trim вне диапазона 1–200 символов отклоняй со статусом 422 при POST и PATCH.',
            '- Явный `null` для `title` или `completed` в POST/PATCH отклоняй со статусом 400.',
            '- Пустой PATCH `{}` существующего ID отклоняй со статусом 400.',
            '- Для отсутствующего ID при GET, PATCH и DELETE возвращай ровно статус 404 и JSON `{"detail":"Todo not found"}` независимо от тела запроса: проверка ID предшествует проверке PATCH.',
        )
        for line in required:
            with self.subTest(line=line):
                self.assertIn(line,task)

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
