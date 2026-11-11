"""Cache identity without starting or importing the JVM."""
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import platform

EXTRACTION_VERSION = 1


def _lastrun_install_dir(environ=os.environ):
    """Mirror pyghidra.launcher._lastrun(): the fallback used when
    GHIDRA_INSTALL_DIR is unset. Reimplemented so jpype is never imported."""
    relative = Path('ghidra', 'lastrun')
    if environ.get('XDG_CONFIG_HOME'):
        lastrun = Path(environ['XDG_CONFIG_HOME']) / relative
    elif platform.system() == 'Windows':
        lastrun = Path(environ.get('APPDATA', '')) / relative
    elif platform.system() == 'Darwin':
        lastrun = Path.home() / 'Library' / relative
    else:
        lastrun = Path.home() / '.config' / relative
    try:
        line = lastrun.read_text().splitlines()[0].strip() if lastrun.is_file() else ''
    except (OSError, IndexError):
        return None
    return line or None


def ghidra_install_dir(environ=os.environ):
    """The installation the launcher would start: env var, else lastrun."""
    return environ.get('GHIDRA_INSTALL_DIR') or _lastrun_install_dir(environ)


def _properties(install):
    if not install:
        return {}
    path = Path(install).expanduser() / 'Ghidra' / 'application.properties'
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return {}
    # Keyed by mtime so an in-place Ghidra upgrade is noticed by long-lived GUIs.
    return _read_properties(str(path), stamp)


@lru_cache(maxsize=8)
def _read_properties(path, _stamp):
    try:
        text = Path(path).read_text()
    except OSError:
        return {}
    return dict(line.split('=', 1) for line in text.splitlines()
                if '=' in line and not line.startswith('#'))


@lru_cache(maxsize=1)
def _pyghidra_version():
    try:
        return version('pyghidra')
    except PackageNotFoundError:
        return None


def analyzer_versions():
    properties = _properties(ghidra_install_dir())
    return {'extraction': EXTRACTION_VERSION, 'pyghidra': _pyghidra_version(),
            'ghidra': properties.get('application.version'),
            'ghidra_revision': properties.get('application.revision.ghidra')}
