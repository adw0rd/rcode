#!/usr/bin/env python3
"""Упаковать проверенный бинарник без локальных данных и файлов проекта."""
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def main(target, ref):
    root = pathlib.Path(__file__).resolve().parent.parent
    version = re.search(r'^version = "([^"]+)"', (root / 'Cargo.toml').read_text(encoding='utf-8'), re.M).group(1)
    if ref.startswith('refs/tags/') and ref != 'refs/tags/v' + version:
        raise SystemExit('Тег не совпадает с версией Cargo.toml')
    filename = 'rcode.exe' if 'windows' in target else 'rcode'
    binary = root / 'target' / target / 'release' / filename
    result = subprocess.run([str(binary), '--version'], check=True, capture_output=True, text=True)
    if result.stdout.strip() != 'rcode ' + version:
        raise SystemExit('Версия бинарника не совпадает с Cargo.toml')
    destination = root / 'dist'
    destination.mkdir(exist_ok=True)
    stem = 'rcode-v' + version + '-' + target
    with tempfile.TemporaryDirectory(prefix='rcode-archive-') as temp:
        directory = pathlib.Path(temp) / stem
        directory.mkdir()
        files = [(binary, filename), (root / 'LICENSE', 'LICENSE')]
        for source, name in files:
            (directory / name).write_bytes(source.read_bytes())
        (directory / 'README.md').write_text(
            '# rcode ' + version + '\n\n'
            'Распакуйте архив, добавьте rcode в PATH и запустите его из папки проекта.\n\n'
            'Руководство: https://github.com/adw0rd/rcode/tree/v' + version + '\n',
            encoding='utf-8',
        )
        if filename == 'rcode':
            (directory / filename).chmod(0o755)
        if 'windows' in target:
            path = destination / (stem + '.zip')
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for item in sorted(directory.iterdir()):
                    archive.write(item, arcname=stem + '/' + item.name)
        else:
            path = destination / (stem + '.tar.gz')
            with tarfile.open(path, 'w:gz') as archive:
                archive.add(directory, arcname=stem)
    print(path.name)


if __name__ == '__main__':
    main(*sys.argv[1:])
