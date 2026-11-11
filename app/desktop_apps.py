"""Linux desktop application catalogue for sing-box process routing.

Desktop launchers supply names and themed icons, not authoritative process
identities. We only offer launchers whose actual executable can be resolved;
Flatpak/other wrappers must be chosen from running processes instead of
routing every process named `flatpak` (or `python`, `env`, ...).
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path
import shlex
import shutil
from dataclasses import dataclass, replace
from typing import Iterable


WRAPPERS = frozenset({
    'env', 'flatpak', 'snap', 'snap-exec', 'sh', 'bash', 'dash', 'zsh', 'fish',
    'python', 'python2', 'python3', 'node', 'electron', 'gtk-launch',
    'dbus-launch', 'dbus-run-session', 'xdg-open', 'gio', 'pkexec',
})


@dataclass(frozen=True)
class DesktopApp:
    name: str
    path: str
    process_name: str = ''
    icon: str = ''
    desktop_id: str = ''
    running: bool = False
    source: str = 'installed'

    def rule(self) -> dict[str, str]:
        # The binary path is more exact than comm, which can collide among apps.
        return {'name': self.process_name if not self.path else '', 'path': self.path}


def identity(name: str, path: str) -> tuple[str, str]:
    if path:
        return ('path', os.path.normpath(path))
    return ('name', name.casefold().strip())


def desktop_directories(env: dict[str, str] | None = None) -> list[Path]:
    e = os.environ if env is None else env
    if env is None:
        # A sudo-launched GUI must still show the desktop applications of the
        # actual login user, not only launchers from root's home.
        from app.app_paths import _home_dir
        home = _home_dir()
    else:
        home = Path(e.get('HOME') or str(Path.home()))
    data_home = Path(e.get('XDG_DATA_HOME') or str(home / '.local/share'))
    data_dirs = (e.get('XDG_DATA_DIRS') or '/usr/local/share:/usr/share').split(':')
    roots = [data_home, *(Path(value) for value in data_dirs if value)]
    return list(dict.fromkeys(root / 'applications' for root in roots))


def _launcher_executable(command: str, *, which=shutil.which) -> str:
    """Return exact executable or empty for launchers with ambiguous wrappers."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return ''
    if not tokens:
        return ''
    first = tokens[0]
    if Path(first).name == 'env':
        # Common desktop launchers use `env FOO=1 /path/to/app`.
        # Skip only plain assignments; flags / shell dispatch are ambiguous.
        remaining = tokens[1:]
        while remaining and '=' in remaining[0] and not remaining[0].startswith('-'):
            remaining.pop(0)
        if not remaining:
            return ''
        first = remaining[0]
    if Path(first).name in WRAPPERS:
        return ''
    # Desktop field codes such as %U are arguments, not executables.
    if '%' in first or first.startswith('~'):
        return ''
    resolved = first if os.path.isabs(first) else which(first)
    if not resolved:
        return ''
    path = Path(resolved)
    try:
        if not path.is_file() or not os.access(path, os.X_OK):
            return ''
        return str(path.resolve())
    except OSError:
        return ''


def _localized_name(section: configparser.SectionProxy, lang: str) -> str:
    language = lang.split('.', 1)[0].split('@', 1)[0].replace('-', '_')
    variants = [language]
    if '_' in language:
        variants.append(language.split('_', 1)[0])
    for variant in variants:
        value = section.get(f'Name[{variant}]', '').strip()
        if value:
            return value
    return section.get('Name', '').strip()


def read_desktop_file(path: Path, *, lang: str = '', which=shutil.which) -> DesktopApp | None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # desktop files are case-sensitive; preserve Name[ru] keys
    try:
        with path.open(encoding='utf-8-sig') as stream:
            parser.read_file(stream)
    except (OSError, UnicodeError, configparser.Error):
        return None
    if not parser.has_section('Desktop Entry'):
        return None
    section = parser['Desktop Entry']
    if (section.get('Type', 'Application') != 'Application'
            or section.get('Hidden', '').lower() == 'true'
            or section.get('NoDisplay', '').lower() == 'true'):
        return None
    name = _localized_name(section, lang or os.environ.get('LC_MESSAGES') or os.environ.get('LANG', ''))
    executable = _launcher_executable(section.get('Exec', ''), which=which)
    if not name or not executable:
        return None
    return DesktopApp(name=name, path=executable, process_name=Path(executable).name,
                      icon=section.get('Icon', '').strip(), desktop_id=path.name)


def installed_applications(roots: Iterable[Path] | None = None, *, lang: str = '') -> list[DesktopApp]:
    result: dict[tuple[str, str], DesktopApp] = {}
    visited_ids: set[str] = set()
    for root in (roots if roots is not None else desktop_directories()):
        if not root.is_dir():
            continue
        try:
            launchers = sorted(root.rglob('*.desktop'))
        except OSError:
            continue
        for launcher in launchers:
            # User overrides take priority, including hidden entries.
            desktop_id = str(launcher.relative_to(root)).replace(os.sep, '-')
            if desktop_id in visited_ids:
                continue
            visited_ids.add(desktop_id)
            app = read_desktop_file(launcher, lang=lang)
            if app:
                key = identity(app.process_name, app.path)
                result.setdefault(key, app)
    return sorted(result.values(), key=lambda app: app.name.casefold())


def running_applications(proc: Path | str = '/proc', *, self_pid: int | None = None) -> list[DesktopApp]:
    found: dict[tuple[str, str], DesktopApp] = {}
    proc_path = Path(proc)
    self_pid = os.getpid() if self_pid is None else self_pid
    # Exclude daemons owned by other users; when run with sudo, show the
    # desktop user's processes instead of root's system services.
    try:
        target_uid = int(os.environ.get('SUDO_UID', str(os.getuid())))
    except (ValueError, AttributeError):
        target_uid = None
    try:
        entries = list(proc_path.iterdir())
    except OSError:
        return []
    for directory in entries:
        if not directory.name.isdecimal() or int(directory.name) == self_pid:
            continue
        try:
            if target_uid is not None and directory.stat().st_uid != target_uid:
                continue
            comm = (directory / 'comm').read_text(encoding='utf-8').strip()
            raw_path = os.readlink(directory / 'exe')
        except (OSError, UnicodeError):
            continue
        if not comm or not raw_path or raw_path.startswith('['):
            continue
        executable = raw_path.removesuffix(' (deleted)')
        if not os.path.isabs(executable) or Path(executable).name in WRAPPERS:
            continue
        key = identity(comm, executable)
        found[key] = DesktopApp(comm, executable, comm, running=True, source='running')
    return sorted(found.values(), key=lambda app: app.name.casefold())


def merge_applications(installed: Iterable[DesktopApp], running: Iterable[DesktopApp],
                       saved_rules: Iterable[dict[str, str]]) -> list[DesktopApp]:
    """Match by executable first; retain selected apps even when they are closed."""
    apps: dict[tuple[str, str], DesktopApp] = {}
    for app in installed:
        apps[identity(app.process_name, app.path)] = app
    for app in running:
        key = identity(app.process_name, app.path)
        if key in apps:
            apps[key] = replace(apps[key], running=True)
        else:
            apps[key] = app
    for rule in saved_rules:
        name, path = rule.get('name', ''), rule.get('path', '')
        key = identity(name, path)
        if key not in apps and (path or name):
            apps[key] = DesktopApp(name=Path(path).name if path else name,
                                   path=path, process_name=name, source='saved')
    return sorted(apps.values(), key=lambda app: (not app.running, app.name.casefold()))
