#!/usr/local/bin/python3 -IS
"""Pinned image SDK entrypoints, independent of a solver's env allowlist.

No HOME initialization or project/config imports. The immutable image supplies
the executables; the command itself still runs with the caller's UID/caps.
"""
import os
from pathlib import Path
import sys


def main():
    tool = Path(sys.argv[0]).name
    if tool not in ('cargo', 'rustc', 'rustdoc', 'rustup'):
        raise SystemExit('unsupported pinned toolchain entrypoint')
    installed = list(Path('/usr/local/rustup/toolchains').glob('*/bin'))
    if len(installed) != 1:
        raise SystemExit('runtime requires exactly one pinned Rust toolchain')
    env = os.environ.copy()
    for name, value in {
        'RUSTUP_HOME': '/usr/local/rustup',
        'CARGO_HOME': '/agent-tmp/cargo-home',
        'CARGO_TARGET_DIR': '/agent-tmp/cargo-target',
    }.items():
        env.setdefault(name, value)
    # Absolute original rustup shims preserve toolchain selection and argv[0]
    # semantics without searching our wrapper directory again.
    executable = Path('/usr/local/cargo/bin') / tool
    os.execve(executable, [str(executable), *sys.argv[1:]], env)


if __name__ == '__main__':
    main()
