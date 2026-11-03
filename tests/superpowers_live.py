"""Opt-in live Superpowers + local model checks; no cloud provider or credentials.

RCODE_SUPERPOWERS_LIVE=1 RCODE_BIN=/path/to/rcode RCODE_LIVE_MODEL=model \
  python3 tests/superpowers_live.py -v

The unchanged MIT corpus and provenance live in fixtures/superpowers-upstream.
Offline transport checks are in skills_activation.rs. Live checks assert actual
receipts, file changes and independent unittest results, never just model prose.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit

CORPUS = Path(__file__).parent / 'fixtures' / 'superpowers-upstream' / 'skills'
ENABLED = os.environ.get('RCODE_SUPERPOWERS_LIVE') == '1'


def arguments(event):
    value = event.get('arguments', {})
    return json.loads(value) if isinstance(value, str) else value


def receipt(event):
    try:
        return json.loads(event.get('content', '{}'))
    except (TypeError, ValueError):
        return {}


@unittest.skipUnless(ENABLED and os.name == 'posix', 'explicit opt-in and POSIX local runtime required')
class SuperpowersLive(unittest.TestCase):
    def setUp(self):
        self.binary = str(Path(os.environ['RCODE_BIN']).resolve())
        self.model = os.environ['RCODE_LIVE_MODEL']
        endpoint = os.environ.get('RCODE_LIVE_BASE_URL', 'http://127.0.0.1:8080/v1')
        url = urlsplit(endpoint)
        self.assertIn(url.hostname, ('127.0.0.1', 'localhost', '::1'))
        self.assertIn(url.scheme, ('http', 'https'))
        self.assertIsNone(url.username)
        self.temp = tempfile.TemporaryDirectory(prefix='rcode-superpowers-live-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(self.root / 'home'),
                    'RCODE_HOME': str(self.root / 'state'), 'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_CONFIG_GLOBAL': os.devnull}
        Path(self.env['HOME']).mkdir()
        self.cli('local', 'add', 'live', '--base-url', endpoint, '--model', self.model,
                 '--runtime', 'mlx', '--context-tokens', os.environ.get('RCODE_LIVE_CONTEXT', '131072'),
                 '--max-output-tokens', '4096', '--activate', '--json')
        self.cli('skills', 'link', str(CORPUS.resolve()), '--name', 'superpowers', '--json')
        self.write('README.md', 'total(values) returns the arithmetic sum, counting duplicates. Empty input gives 0. Run python3 -m unittest -v.\n')
        self.write('prices.py', 'def total(values):\n    return sum(set(values))\n')
        self.write('test_prices.py', 'import unittest\nfrom prices import total\n\nclass PricesTest(unittest.TestCase):\n    def test_empty(self):\n        self.assertEqual(total([]), 0)\n    def test_sum(self):\n        self.assertEqual(total([2, 3]), 5)\n')
        for args in [('init', '-q', '-b', 'main'), ('config', 'user.name', 'Live Fixture'),
                     ('config', 'user.email', 'fixture@example.invalid'), ('add', '.'),
                     ('commit', '-q', '-m', 'Initial fixture')]:
            subprocess.run(['git', *args], cwd=self.project, env=self.env,
                           capture_output=True, check=True, timeout=15)

    def write(self, name, body):
        (self.project / name).write_text(body)

    def cli(self, *args):
        run = subprocess.run([self.binary, '-C', str(self.project), *args],
                             env=self.env, capture_output=True, text=True, timeout=40)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run

    def sources(self):
        return {name: (self.project / name).read_bytes()
                for name in ('README.md', 'prices.py', 'test_prices.py')}

    def turn(self, prompt, plan=False):
        argv = [self.binary, '-C', str(self.project), '--profile', 'live', '--json',
                '--max-steps', '24', '--approval-mode', 'auto-edit']
        argv += ['--plan'] if plan else ['--allow-shell']
        argv += ['exec', prompt]
        binary_sha256 = hashlib.sha256(Path(self.binary).read_bytes()).hexdigest()
        started = time.monotonic()
        timed_out = False
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(argv, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = process.wait(timeout=480)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = process.returncode
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            stdout.seek(0)
            events = [json.loads(line) for line in stdout.read().splitlines() if line]
            stderr.seek(0)
            error = stderr.read().decode(errors='replace')
        text = ''.join(e.get('text', '') for e in events if e['type'] == 'text')
        artifact = {'exit_code': code, 'timeout': timed_out, 'seconds': round(time.monotonic() - started, 3),
                    'text': text, 'events': events, 'stderr': error,
                    'binary_sha256': binary_sha256}
        directory = os.environ.get('RCODE_LIVE_ARTIFACT_DIR')
        if directory:
            target = Path(directory)
            target.mkdir(parents=True, exist_ok=True)
            (target / (self._testMethodName + '.json')).write_text(json.dumps(artifact, ensure_ascii=False, indent=2))
        print(f'\n{self._testMethodName}: exit={code}, {artifact["seconds"]}s', flush=True)
        self.assertFalse(timed_out, 'local model exceeded bounded live deadline; no success claimed')
        self.assertEqual(code, 0, text[-1600:] + error[-1000:])
        return events, text

    def loaded(self, events, name):
        return any(e['type'] == 'tool_start' and e.get('name') == 'load_skill'
                   and arguments(e).get('name') == 'superpowers:' + name for e in events)

    def test_tdd_writes_regression_observes_red_then_fix_then_green(self):
        before = self.sources()
        events, _ = self.turn('Используй superpowers:using-superpowers, superpowers:test-driven-development и superpowers:verification-before-completion. Исправь баг: total([2,2,3]) должен давать 7, сейчас даёт 5. Контракт README утверждён, дизайн и план для такого исправления уже согласованы. Добавь регрессию и минимальное исправление, проверь результат. Без коммитов, сети, установки и изменений README. Итог кратко по-русски.')
        for name in ('using-superpowers', 'test-driven-development', 'verification-before-completion'):
            self.assertTrue(self.loaded(events, name), 'required original skill was not loaded: ' + name)
        red = [i for i,e in enumerate(events) if e['type']=='tool_result' and e.get('name')=='run_command'
               and 'FAILED' in str(receipt(e)) and '5 != 7' in str(receipt(e))]
        self.assertTrue(red, 'no actual regression failure observed')
        writes = [i for i,e in enumerate(events) if e['type']=='tool_result'
                  and 'prices.py' in e.get('changed_paths', []) and not e.get('is_error')]
        self.assertTrue(writes, 'production edit must be visible in tool receipts')
        self.assertLess(red[0], writes[0], 'production changed before observed RED')
        green = [i for i,e in enumerate(events) if e['type']=='tool_result' and e.get('name')=='run_command'
                 and receipt(e).get('exit_code')==0 and 'OK' in str(receipt(e))]
        self.assertTrue(any(i>writes[0] for i in green), 'no real GREEN after fix')
        self.assertEqual((self.project/'README.md').read_bytes(), before['README.md'])
        self.assertNotEqual((self.project/'test_prices.py').read_bytes(), before['test_prices.py'])
        run = subprocess.run([sys.executable, '-m', 'unittest', '-v'], cwd=self.project,
                             env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        check = subprocess.run([sys.executable, '-c', 'from prices import total; assert total([2,2,3])==7; assert total([])==0'],
                               cwd=self.project, env=self.env, capture_output=True, timeout=10)
        self.assertEqual(check.returncode, 0, check.stderr)
        # Prove the new test detects the original bug, rather than mirroring a fix.
        fixed = (self.project/'prices.py').read_bytes()
        (self.project/'prices.py').write_bytes(before['prices.py'])
        try:
            run = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v'], cwd=self.project,
                                 env={**self.env, 'PYTHONDONTWRITEBYTECODE':'1'}, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(run.returncode, 0, 'new regression also passes on the original buggy implementation')
        finally:
            (self.project/'prices.py').write_bytes(fixed)

    def test_plan_loads_original_skill_without_shell_or_writes(self):
        before = self.sources()
        events, text = self.turn('Используй superpowers:using-superpowers и superpowers:verification-before-completion. В режиме plan прочитай проект и предложи план проверки ошибки total([2,2,3]). Ничего не исправляй; shell и запуск тестов запрещены. Не утверждай, что тесты пройдены. Итог до 120 слов по-русски.', plan=True)
        self.assertTrue(self.loaded(events, 'using-superpowers'))
        self.assertTrue(self.loaded(events, 'verification-before-completion'))
        self.assertTrue(text.strip())
        self.assertEqual(self.sources(), before)
        for e in events:
            if e['type']=='tool_start':
                self.assertNotIn(e.get('name'), ('run_command','write_file','edit_file','apply_patch'))

    def test_requesting_review_dispatches_and_collects_reviewer_without_edits(self):
        before = self.sources()
        events, text = self.turn('Используй superpowers:using-superpowers и superpowers:requesting-code-review. Проведи ревью prices.py относительно контракта README с отдельным reviewer. Ревью без исправлений; ничего не меняй и не коммить. Дождись результата reviewer, подтверди конкретную строку и проблему на повторяющихся значениях. Ответ до 150 слов по-русски.')
        self.assertTrue(self.loaded(events, 'requesting-code-review'))
        spawns = [e for e in events if e['type']=='tool_start' and e.get('name')=='spawn_agent']
        self.assertTrue(any(arguments(e).get('role')=='reviewer' for e in spawns), 'no real reviewer dispatch')
        created = [receipt(e) for e in events if e['type']=='tool_result'
                   and e.get('name')=='spawn_agent' and not e.get('is_error')]
        reviewer_ids = {r['id'] for r in created if r.get('role')=='reviewer' and r.get('id')}
        self.assertTrue(reviewer_ids, 'reviewer creation did not succeed')
        completed = [receipt(e) for e in events if e['type']=='tool_result'
                     and e.get('name')=='wait_agent' and not e.get('is_error')]
        self.assertTrue(any(r.get('id') in reviewer_ids and r.get('status')=='completed'
                            and 'prices.py' in r.get('result', '') for r in completed),
                        'no actual completed reviewer result was collected')
        self.assertIn('prices.py', text)
        self.assertEqual(self.sources(), before)


if __name__ == '__main__':
    unittest.main()
