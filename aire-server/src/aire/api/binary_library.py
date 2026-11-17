"""Local binary intake and serialized static analysis for the standard-library GUI.

Only allowlisted binary paths reach the indexer. Source/ground truth are never
read here. One long-lived worker owns its SQLite writer and Ghidra lifecycle.
"""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from aire.analysis.cache import compatible_metadata
from aire.validation.pe_structure import validate_pe
from aire.security.rule_engine import _ReadOnlyRuleStore

MAX_UPLOAD = 32 * 1024 * 1024
REPOSITORY = Path(__file__).resolve().parents[4]
MAX_REPORTED_ISSUES = 50
DEFAULT_ANALYSIS_TIMEOUT = 3600  # seconds; large PEs take >15 min cold


class BinaryValidationError(ValueError):
    """Rejected intake with a structured, JSON-safe validation report."""

    def __init__(self, message, report=None):
        super().__init__(message)
        self.report = report


def redact_paths(text):
    """Replace this machine's absolute repository/home prefixes in client-visible messages."""
    text = str(text)
    for prefix, label in ((str(REPOSITORY), '<repo>'), (str(Path.home()), '~')):
        if len(prefix) > 1:
            text = text.replace(prefix, label)
    return text


def _pe_fields(report):
    issues = [vars(issue) for issue in report.issues]
    return {'pe_valid': report.pe_valid, 'analysis_level': report.analysis,
            'structure_summary': report.summary, 'structure_issue_count': len(issues),
            'structure_issues': issues[:MAX_REPORTED_ISSUES]}


def inspect_binary(path):
    """Validate actual ELF/PE headers and file-backed sections without execution."""
    path = Path(path)
    size = path.stat().st_size
    if not 0 < size <= MAX_UPLOAD:
        raise ValueError('Binary must be between 1 byte and 32 MiB')
    data = path.read_bytes()
    def require(condition):
        if not condition:
            raise ValueError('Malformed or truncated ELF/PE binary')
    if data.startswith(b'\x7fELF'):
        require(len(data) >= 52 and data[4] in (1, 2) and data[5] in (1, 2) and data[6] == 1)
        bits = 32 if data[4] == 1 else 64
        endian = '<' if data[5] == 1 else '>'
        header_size = 52 if bits == 32 else 64
        require(len(data) >= header_size)
        kind, machine, version = struct.unpack_from(endian + 'HHI', data, 16)
        require(kind in (2, 3) and version == 1)
        if bits == 32:
            phoff, shoff = struct.unpack_from(endian + 'II', data, 28)
        else:
            phoff, shoff = struct.unpack_from(endian + 'QQ', data, 32)
        ehsize, phsize, phnum, shsize, shnum, _ = struct.unpack_from(endian + '6H', data, 40 if bits == 32 else 52)
        require(ehsize == header_size and phnum > 0 and phnum != 0xffff)
        require(phsize >= (32 if bits == 32 else 56) and phoff >= header_size and phoff + phnum * phsize <= size)
        require(not shnum or (shsize >= (40 if bits == 32 else 64) and shoff + shnum * shsize <= size))
        for i in range(phnum):
            off = phoff + i * phsize
            if bits == 32:
                offset = struct.unpack_from(endian + 'I', data, off + 4)[0]
                filesz = struct.unpack_from(endian + 'I', data, off + 16)[0]
            else:
                offset = struct.unpack_from(endian + 'Q', data, off + 8)[0]
                filesz = struct.unpack_from(endian + 'Q', data, off + 32)[0]
            require(not filesz or offset + filesz <= size)
        architecture = {3: 'x86', 62: 'x86_64', 40: 'ARM', 183: 'AArch64', 243: 'RISC-V'}.get(machine, f'ELF machine {machine}')
        fmt = 'ELF'
    elif data.startswith(b'MZ'):
        # Structured PE validation (aire.validation.pe_structure). Header-level
        # corruption is rejected with specific reasons; damage a loader can
        # tolerate (truncated sections, malformed imports) is accepted for
        # partial analysis and the issues travel with the upload/job.
        report = validate_pe(data)
        fields = _pe_fields(report)
        if report.analysis == 'none':
            reasons = '; '.join(i.message for i in report.issues if i.severity == 'fatal')
            raise BinaryValidationError(f'Malformed or truncated PE binary: {reasons}',
                                        {**fields, 'format': report.format,
                                         'architecture': report.architecture, 'bits': report.bits,
                                         'size': size})
        return {'format': 'PE', 'architecture': report.architecture, 'bits': report.bits,
                'size': size, 'sha256': hashlib.sha256(data).hexdigest(), **fields}
    else:
        report = validate_pe(data)  # explains near-miss signatures such as b'ZM'
        raise BinaryValidationError(
            'Select an ELF executable/shared object or Windows PE binary; file extensions are not trusted',
            {**_pe_fields(report), 'format': None, 'size': size})
    return {'format': fmt, 'architecture': architecture, 'bits': bits,
            'size': size, 'sha256': hashlib.sha256(data).hexdigest(),
            'pe_valid': None, 'analysis_level': 'full', 'structure_summary': 'Valid ELF headers',
            'structure_issue_count': 0, 'structure_issues': []}


class BinaryLibrary:
    def __init__(self, database, *, directory=None, repository=None):
        self.database = Path(database)
        self.repository = Path(repository or REPOSITORY).resolve()
        self.directory = Path(directory or self.database.parent / '.aire-uploads').resolve()
        self._lock = threading.RLock()
        self._uploads = OrderedDict()
        self._jobs = OrderedDict()
        self._executor = None
        self._process = None
        self._worker_log = None
        try:
            timeout = float(os.environ.get('AIRE_ANALYSIS_TIMEOUT', DEFAULT_ANALYSIS_TIMEOUT))
        except ValueError:
            timeout = DEFAULT_ANALYSIS_TIMEOUT
        self.analysis_timeout = timeout if timeout > 0 else DEFAULT_ANALYSIS_TIMEOUT
        self._fixtures = self._load_fixtures()

    def _load_fixtures(self):
        fixtures = {}
        for relative, collection, prefix in (
            ('tests/fixtures/external', 'Imported benchmarks', 'external:'),
            ('tests/fixtures/m9', 'M9 fixtures', 'm9:'),
        ):
            root = self.repository / relative
            manifest = root / 'manifest.json'
            try:
                rows = json.loads(manifest.read_text())['fixtures'] if manifest.is_file() else []
            except (OSError, ValueError, KeyError) as exc:
                rows = []
                fixtures[prefix + 'manifest'] = {'name': f'{relative}/manifest.json', 'path': manifest,
                                                 'expected_sha256': None, 'collection': collection,
                                                 'load_error': f'Unreadable manifest: {exc}'}
            for row in rows:
                path = (root / row['binary_path']).resolve()
                if not path.is_relative_to(root.resolve()):
                    raise ValueError('Fixture path escapes repository fixture directory')
                fixtures[prefix + row['name']] = {
                    'name': row['name'], 'path': path, 'expected_sha256': row['binary_sha256'],
                    'collection': row.get('collection', collection), 'upstream_url': row.get('upstream_url'),
                    'negative_fixture': row.get('negative_fixture', False),
                    'expected_analysis': row.get('expected_analysis')}
        for key, name, relative in (
            ('professor:overloading', 'FunctionOverloading.exe', 'professor_samples/function_overloading/original/FunctionOverloading.exe'),
            ('local:simple-elf', 'aire_test_binary', 'tests/fixtures/simple_elf/aire_test_binary'),
        ):
            path = (self.repository / relative).resolve()
            if path.is_file():
                # Optional demo binaries must never abort GUI startup: a
                # truncated/unreadable file is listed as unavailable instead.
                try:
                    expected = inspect_binary(path)['sha256']
                except (OSError, ValueError) as exc:
                    expected, error = None, str(exc)
                else:
                    error = None
                fixtures[key] = {'name': name, 'path': path, 'expected_sha256': expected,
                                 'collection': 'Local demo', **({'load_error': error} if error else {})}
        return fixtures

    def list(self):
        with _ReadOnlyRuleStore(self.database) as store:
            stored = {b.binary_id: b for b in store.list_binaries()}
            # Only small metadata is loaded; never all functions or source bodies.
            all_metadata = {}
            for row in store._db.execute('SELECT binary_id,key,value FROM analysis_metadata'):
                if row[1] in ('options', 'analyzer_versions', 'reference_facts_version', 'ghidra_version',
                              'instruction_ir'):
                    all_metadata.setdefault(row[0], {})[row[1]] = json.loads(row[2])
        rows = []
        for key, fixture in self._fixtures.items():
            row = {k:v for k,v in fixture.items() if k not in ('path', 'expected_sha256', 'load_error')
                   and v is not None}
            row['fixture_id'] = key
            row['binary_path'] = str(fixture['path'].relative_to(self.repository))
            try:
                if fixture.get('load_error'):
                    raise ValueError(fixture['load_error'])
                row.update(inspect_binary(fixture['path']))
                if row['sha256'] != fixture['expected_sha256']:
                    raise ValueError('Fixture SHA-256 differs from manifest; analysis disabled')
                row['available'] = True
                row['indexed'] = row['sha256'] in stored
                row['cached'] = row['indexed'] and compatible_metadata(all_metadata.get(row['sha256'], {}))
            except (OSError, ValueError) as exc:
                row.update(available=False, cached=False, indexed=False, error=redact_paths(exc.strerror if isinstance(exc, OSError) and exc.strerror else exc),
                           sha256=fixture['expected_sha256'])
                if getattr(exc, 'report', None):
                    row['validation'] = exc.report
            rows.append(row)
        return rows

    def upload(self, stream, length, filename):
        if not 0 < length <= MAX_UPLOAD:
            raise ValueError('Upload must be between 1 byte and 32 MiB')
        # Client filenames are display labels only, never directories.
        filename = str(filename).replace('\\', '/').rsplit('/', 1)[-1]
        filename = re.sub(r'[^A-Za-z0-9_.-]', '_', filename)[:120].strip('.') or 'binary'
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(dir=self.directory, prefix='.upload-', delete=False) as output:
            temporary = Path(output.name)
            try:
                remaining = length
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError('Incomplete upload')
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                details = inspect_binary(temporary)
                target_dir = self.directory / details['sha256']
                if target_dir.is_symlink():
                    raise ValueError('Unsafe upload storage directory')
                target_dir.mkdir(mode=0o700, exist_ok=True)
                target = target_dir / filename
                if target.is_symlink():
                    raise ValueError('Unsafe upload storage path')
                if target.exists():
                    if inspect_binary(target)['sha256'] != details['sha256']:
                        raise ValueError('Stored upload integrity mismatch')
                else:
                    temporary.replace(target)
                    target.chmod(0o600)
            finally:
                temporary.unlink(missing_ok=True)
        token = uuid4().hex
        details.update(upload_id=token, filename=filename)
        with self._lock:
            self._uploads[token] = (target, details)
            while len(self._uploads) > 128:
                self._uploads.popitem(last=False)
        return details

    def start(self, *, upload_id=None, fixture_id=None):
        if bool(upload_id) == bool(fixture_id):
            raise ValueError('Select exactly one upload or repository fixture')
        with self._lock:
            if sum(j['status'] in ('queued', 'running') for j in self._jobs.values()) >= 8:
                raise ValueError('Analysis queue is full; wait for current work to complete')
            if fixture_id:
                fixture = self._fixtures.get(fixture_id)
                if not fixture:
                    raise ValueError('Unknown repository fixture')
                if fixture.get('load_error') or not fixture['expected_sha256']:
                    raise ValueError(f"Fixture unavailable: {fixture.get('load_error', 'no verified SHA-256')}")
                path, expected, name = fixture['path'], fixture['expected_sha256'], fixture['name']
            else:
                upload = self._uploads.get(upload_id)
                if not upload:
                    raise ValueError('Upload expired or not found; select the file again')
                path, details = upload
                expected, name = details['sha256'], details['filename']
            details = inspect_binary(path)
            if details['sha256'] != expected:
                raise ValueError('Binary SHA-256 changed; analysis disabled')
            # Coalesce repeated clicks while the same binary is queued/running.
            for job in self._jobs.values():
                if job['sha256'] == expected and job['status'] in ('queued', 'running'):
                    return self.job(job['job_id'])
            key = uuid4().hex
            self._jobs[key] = {**details, 'job_id': key, 'filename': name,
                               'status': 'queued', 'phase': 'Waiting for static analysis worker',
                               'events': [], 'submitted': time.time(), '_tick': time.perf_counter()}
            while len(self._jobs) > 64:
                old = next((k for k,v in self._jobs.items() if v['status'] in ('completed','failed')), None)
                if old is None:
                    break
                del self._jobs[old]
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='aire-static-analysis')
            self._executor.submit(self._analyze, key, path, expected)
            return self.job(key)

    def job(self, key):
        with self._lock:
            if key not in self._jobs:
                raise ValueError('Analysis job not found')
            row = deepcopy(self._jobs[key])
        row['elapsed_seconds'] = row.get('total_seconds', time.perf_counter() - row['_tick'])
        del row['_tick']
        return row

    def _update(self, key, **values):
        with self._lock:
            self._jobs[key].update(values)

    def _analyze(self, key, path, expected):
        started = time.perf_counter()
        def progress(message):
            with self._lock:
                job = self._jobs[key]
                job['phase'] = message
                job['events'].append({'phase': message, 'seconds': time.perf_counter() - started})
        self._update(key, status='running', queue_seconds=started-self._jobs[key]['_tick'])
        try:
            if inspect_binary(path)['sha256'] != expected:
                raise ValueError('Binary changed while queued')
            result = self._run_analysis(path, progress)
            if result['binary_id'] != expected:
                raise ValueError('Analysis identity differs from submitted SHA-256')
            self._update(key, **result)
        except Exception as exc:
            self._update(key, status='failed', phase='Static analysis failed', error=redact_paths(exc)[:500])
        finally:
            self._update(key, status='failed' if 'error' in self._jobs[key] else 'completed',
                         total_seconds=time.perf_counter()-self._jobs[key]['_tick'])
            # Durable timings outside the analysis snapshot; reopening the GUI
            # does not mislabel the original index time as cache request time.
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            (self.directory / (key + '.job.json')).write_text(json.dumps(self.job(key), indent=2))

    def _ensure_worker(self, prewarm=False):
        """Start the persistent analyzer process if none is alive. Serialized
        with the job thread so pre-warming and a first job never race."""
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return self._process
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self._worker_log:
                self._worker_log.close()
            self._worker_log = (self.directory / 'index-worker.log').open('a')
            command = [sys.executable, '-m', 'aire.api.index_worker', str(self.database.resolve())]
            if prewarm:
                self.prewarm_status_path.unlink(missing_ok=True)
                command.append(f'--prewarm={self.prewarm_status_path}')
            self._process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._worker_log,
                text=True, bufsize=1)
            self._prewarm_requested = prewarm
            return self._process

    @property
    def prewarm_status_path(self):
        return self.directory / 'prewarm.json'

    def prewarm(self):
        """Non-blocking: spawn the analyzer now so JVM/Ghidra start-up runs
        while the user is still choosing a file. No binary is analysed. Any
        failure leaves the normal lazy start-up path in place."""
        try:
            self._ensure_worker(prewarm=True)
            return True
        except Exception as exc:
            self._prewarm_error = str(exc)[:500]
            return False

    def analyzer_status(self):
        process = self._process
        if getattr(self, '_prewarm_error', None):
            return {'status': 'failed', 'error': self._prewarm_error, 'fallback': 'starts on first analysis'}
        if process is None:
            return {'status': 'not_started', 'fallback': 'starts on first analysis'}
        if process.poll() is not None:
            return {'status': 'stopped', 'fallback': 'restarts on next analysis'}
        if not getattr(self, '_prewarm_requested', False):
            return {'status': 'running'}
        try:
            return json.loads(self.prewarm_status_path.read_text())
        except (OSError, ValueError):
            return {'status': 'warming'}

    def _run_analysis(self, path, progress):
        process = self._ensure_worker()
        # Watchdog: a malformed input that hangs the analyzer must not block
        # the queue forever. Killing the child ends its stdout; the next job
        # starts a fresh worker. The target file itself is never touched.
        timed_out = threading.Event()
        def expire():
            timed_out.set()
            try:
                process.kill()
            except OSError:
                pass
        watchdog = threading.Timer(self.analysis_timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            process.stdin.write(json.dumps({'path': str(path.resolve())}) + '\n')
            process.stdin.flush()
            for line in process.stdout:
                packet = json.loads(line)
                if packet['type'] == 'progress':
                    progress(packet['data'])
                elif packet['type'] == 'completed':
                    return packet['data']
                elif packet['type'] == 'failed':
                    raise ValueError(packet['data'])
            if timed_out.is_set():
                raise RuntimeError(f'Static analysis exceeded {self.analysis_timeout:g} s and was stopped; '
                                   'the analyzer restarts for the next job')
            raise RuntimeError('Static analyzer process stopped unexpectedly; retry the analysis')
        except (BrokenPipeError, json.JSONDecodeError) as exc:
            raise RuntimeError('Static analyzer communication failed; retry the analysis') from exc
        finally:
            watchdog.cancel()

    def close(self):
        if self._executor:
            self._executor.shutdown(wait=True)
        if self._process:
            if self._process.poll() is None:
                self._process.stdin.close()
                try:
                    self._process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                        self._process.wait()
            for stream in (self._process.stdin, self._process.stdout):
                stream.close()
        if self._worker_log:
            self._worker_log.close()
