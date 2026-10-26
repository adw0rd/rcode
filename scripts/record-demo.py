#!/usr/bin/env python3
"""Записать реальный CLI в изолированном проекте с уже настроенным GigaChat.

Для записи на macOS/Linux нужны vhs, ttyd, ffmpeg и Python с fastapi, httpx2, pytest.
Секрет вводится только через обычное подключение rcode; в tape его нет.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


def data_directory():
    if os.environ.get('RCODE_HOME'):
        return pathlib.Path(os.environ['RCODE_HOME'])
    home = pathlib.Path.home()
    if sys.platform == 'darwin':
        return home / 'Library/Application Support/rcode'
    if sys.platform == 'win32':
        return pathlib.Path(os.environ['APPDATA']) / 'rcode/config'
    return pathlib.Path(os.environ.get('XDG_CONFIG_HOME') or home / '.config') / 'rcode'


def main():
    if sys.platform == 'win32':
        raise SystemExit('Для записи VHS-демо используйте macOS, Linux или WSL')
    repo = pathlib.Path(__file__).resolve().parent.parent
    source = data_directory()
    settings = json.loads((source / 'config.json').read_text())
    credentials_file = source / 'credentials.json'
    saved = json.loads(credentials_file.read_text()) if credentials_file.exists() else {'providers': {}}
    provider = settings['providers']['gigachat']
    credential = next((os.environ[name] for name in ['RCODE_GIGACHAT_AUTH_KEY', 'GIGACHAT_AUTH_KEY', 'GIGACHAT_CREDENTIALS'] if os.environ.get(name)), None) or saved['providers'].get('gigachat')
    if not credential:
        raise SystemExit('Сначала подключите GigaChat: rcode connect gigachat')
    provider['model'] = 'GigaChat-3-Ultra'
    binary = repo / 'target/release/rcode'
    if not binary.is_file():
        raise SystemExit('Сначала выполните cargo build --release --locked')
    subprocess.run([sys.executable, '-c', 'import fastapi,httpx2,pytest'], check=True)
    with tempfile.TemporaryDirectory(prefix='rcode-demo-', dir='/tmp') as temp:
        root = pathlib.Path(temp)
        project, state, binaries = root / 'fastapi', root / 'state', root / 'bin'
        project.mkdir(); state.mkdir(mode=0o700); binaries.mkdir()
        for name, value in [('config.json', {'version': 1, 'active': 'gigachat', 'providers': {'gigachat': provider}}), ('credentials.json', {'version': 1, 'providers': {'gigachat': credential}})]:
            with os.fdopen(os.open(state / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
                json.dump(value, stream)
        if (source / 'certificates').is_dir():
            shutil.copytree(source / 'certificates', state / 'certificates')
        shutil.copy2(binary, binaries / 'rcode')
        env = {**os.environ, 'RCODE_HOME': str(state), 'RCODE_DEMO_PROJECT': str(project), 'PATH': str(binaries) + os.pathsep + str(pathlib.Path(sys.executable).absolute().parent) + os.pathsep + os.environ['PATH']}
        env.pop('NO_COLOR', None)
        subprocess.run(['vhs', 'docs/demo.tape'], cwd=repo, env=env, check=True, timeout=240)
        result = subprocess.run([sys.executable, '-m', 'pytest', '-q'], cwd=project, capture_output=True, text=True, timeout=30)
        if result.returncode or '2 passed' not in result.stdout:
            raise SystemExit('Созданный проект не прошёл независимую проверку pytest: ' + result.stdout + result.stderr)
        verify = 'from fastapi.testclient import TestClient;from main import app;c=TestClient(app);assert c.get("/health").json()=={"status":"ok"};assert c.get("/greet",params={"name":"Мир"}).json()=={"message":"Привет, Мир!"}'
        subprocess.run([sys.executable, '-c', verify], cwd=project, check=True, timeout=30)
        print('Demo validated: GigaChat-3-Ultra, FastAPI endpoints, 2 passed')


if __name__ == '__main__':
    main()
