"""Fail-closed Linux launcher for static fixture tools (Landlock ABI >=3/seccomp).

Usage: python3 scripts/external_fixture_sandbox.py /tmp/aire-external-run
       /absolute/path/to/python scripts/smoke_external_fixtures.py ...
Use absolute script paths: the child works in the disposable directory.
Only installed static tools/interpreters can be launched. Fixture directories
are readable but cannot be executed or modified. No network sockets are allowed.
This helper needs no pip packages; Linux libseccomp.so.2 must already be installed.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import resource
import sys

ROOT = Path(__file__).resolve().parents[1]


def restrict(work):
    if not work.is_relative_to(Path('/tmp')) or work == Path('/tmp'):
        raise ValueError('Use a dedicated disposable directory beneath /tmp')
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long

    def check(value, label):
        if value < 0:
            raise OSError(ctypes.get_errno(), label)
        return value

    # These syscall numbers apply to Linux x86-64, the AIRE test environment.
    if os.uname().machine != 'x86_64':
        raise RuntimeError('This launcher supports Linux x86-64 only')
    if check(lib.syscall(444, 0, 0, 1), 'Landlock ABI') < 3:
        raise RuntimeError('Landlock ABI >=3 required')
    fs = (1 << 15) - 1  # Execute through truncate, including refer.

    class Ruleset(ctypes.Structure):
        _fields_ = [('handled_access_fs', ctypes.c_uint64)]

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]

    fd = check(lib.syscall(444, ctypes.byref(Ruleset(fs)), 8, 0), 'create ruleset')
    read = (1 << 2) | (1 << 3)
    paths = [(p, read | 1) for p in ('/usr', '/lib', '/lib64', '/bin', '/sbin')]
    paths += [(p, read) for p in ('/etc', '/proc', '/sys')]
    paths += [(str(ROOT / p), read) for p in ('aire-server', 'tests', 'professor_samples', 'scripts', 'docs')]
    ghidra = Path(os.environ.get('GHIDRA_INSTALL_DIR', str(Path.home() / 'tools/ghidra'))).resolve()
    paths += [(str(ghidra), read | 1), ('/dev/null', 6), ('/dev/random', 4), ('/dev/urandom', 4),
              (str(work), fs & ~1)]
    for path, access in paths:
        if not os.path.exists(path):
            continue
        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            check(lib.syscall(445, fd, 1, ctypes.byref(Beneath(access, pfd)), 0), 'allow ' + path)
        finally:
            os.close(pfd)
    check(lib.prctl(38, 1, 0, 0, 0), 'no_new_privs')
    check(lib.syscall(446, fd, 0), 'restrict filesystem')
    os.close(fd)
    sec = ctypes.CDLL('libseccomp.so.2')
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = sec.seccomp_init(0x7fff0000)
    if not ctx:
        raise RuntimeError('seccomp initialization failed')
    for name in ('socket', 'connect', 'bind', 'listen', 'accept', 'accept4', 'ptrace',
                 'mount', 'umount2', 'unshare', 'setns', 'bpf', 'keyctl',
                 'process_vm_readv', 'process_vm_writev', 'reboot', 'kexec_load',
                 'open_by_handle_at', 'io_uring_setup'):
        number = sec.seccomp_syscall_resolve_name(name.encode())
        if number >= 0:
            check(sec.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, number, 0), 'deny ' + name)
    check(sec.seccomp_load(ctx), 'install seccomp')
    sec.seccomp_release(ctx)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
    os.environ.update(TMPDIR=str(work), XDG_CACHE_HOME=str(work / 'cache'),
                      PYTHONDONTWRITEBYTECODE='1', GHIDRA_INSTALL_DIR=str(ghidra),
                      JAVA_HOME=os.environ.get('JAVA_HOME', '/usr/lib/jvm/java-21-openjdk-amd64'),
                      PYTHONPATH=str(ROOT / 'aire-server/src') + ':' + str(ROOT / 'aire-server/tests'))
    os.chdir(work)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    work = Path(sys.argv[1]).resolve()
    args = sys.argv[2:]
    tools = {Path('/usr/bin/' + name).resolve() for name in ('file', 'readelf', 'objdump', 'nm', 'strings', 'python3')}
    tools.add((ROOT / 'aire-server/.venv/bin/python').resolve())
    if args != ['--self-test'] and (not Path(args[0]).is_absolute() or Path(args[0]).resolve() not in tools):
        raise ValueError('Only absolute paths to installed static tools/Python are allowed')
    if not work.is_relative_to(Path('/tmp')) or work == Path('/tmp'):
        raise ValueError('Use a dedicated disposable directory beneath /tmp')
    work.mkdir(parents=True, exist_ok=True)
    restrict(work)
    if args == ['--self-test']:
        import socket
        for operation in (lambda: socket.socket(),
                          lambda: (ROOT / '.git/HEAD').read_bytes(),
                          lambda: (work.parent / 'aire_external_forbidden_write').write_text('denied')):
            try:
                operation()
            except PermissionError:
                continue
            raise AssertionError('Sandbox self-test did not deny access')
        (work / 'self-test.json').write_text(json.dumps(dict(network_denied=True, private_git_denied=True,
                                                          outside_write_denied=True)) + '\n')
        print('PASS: network, private repository metadata and outside writes denied')
    else:
        os.execv(args[0], args)


if __name__ == '__main__':
    main()
