from dataclasses import replace
import os
from pathlib import Path

from app.desktop_apps import (
    DesktopApp, _launcher_executable, desktop_directories, installed_applications,
    merge_applications, read_desktop_file, running_applications,
)


def test_xdg_application_search_paths(tmp_path):
    roots = desktop_directories({'HOME': str(tmp_path), 'XDG_DATA_HOME': str(tmp_path / 'custom'),
                                 'XDG_DATA_DIRS': f'{tmp_path / "usr"}:{tmp_path / "shared"}'})
    assert roots == [tmp_path / 'custom/applications', tmp_path / 'usr/applications',
                     tmp_path / 'shared/applications']


def test_desktop_name_icon_and_executable_resolution(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    executable = bin_dir / 'example'
    executable.write_text('#!/bin/sh\n')
    executable.chmod(0o755)
    desktop = tmp_path / 'Example.desktop'
    desktop.write_text('[Desktop Entry]\nType=Application\nName=Example\nName[ru]=Пример\n'
                       f'Exec={executable} --verbose %U\nIcon=example-theme\n')
    app = read_desktop_file(desktop, lang='ru_RU.UTF-8')
    assert app == DesktopApp('Пример', str(executable), 'example', 'example-theme', 'Example.desktop')
    assert app.rule() == {'name': '', 'path': str(executable)}


def test_ignored_wrappers_cannot_capture_other_apps(tmp_path):
    def which(program):
        return '/usr/bin/' + program
    for command in ['flatpak run org.example.App', 'sh -c app',
                    'python3 -m app', '/usr/bin/snap run example']:
        assert _launcher_executable(command, which=which) == ''


def test_invalid_desktop_entries_and_overrides(tmp_path):
    high = tmp_path / 'user/applications'
    low = tmp_path / 'system/applications'
    high.mkdir(parents=True)
    low.mkdir(parents=True)
    executable = tmp_path / 'myapp'
    executable.write_text('#!/bin/sh\n')
    executable.chmod(0o755)
    launcher = low / 'example.desktop'
    launcher.write_text(f'[Desktop Entry]\nName=System\nExec={executable}\nIcon=system\n')
    (high / 'example.desktop').write_text(f'[Desktop Entry]\nHidden=true\nName=Override\nExec={executable}\n')
    assert installed_applications([high, low]) == []
    (high / 'example.desktop').write_text(f'[Desktop Entry]\nName=User\nExec={executable}\nIcon=my-icon\n')
    assert [x.name for x in installed_applications([high, low])] == ['User']


def test_saved_merged_with_running_using_paths(tmp_path):
    path = '/opt/something/MyApp'
    installed = [DesktopApp('My Application', path, 'MyApp', 'my-icon')]
    running = [DesktopApp('MyApp', path, 'MyApp', running=True, source='running')]
    merged = merge_applications(installed, running, [{'name': 'MyApp', 'path': path},
                                                      {'name': 'legacy', 'path': ''}])
    assert len(merged) == 2
    assert merged[0].name == 'My Application' and merged[0].running
    assert merged[0].icon == 'my-icon'
    assert merged[1].source == 'saved'


def test_running_proc_identity(tmp_path):
    proc = tmp_path / 'proc'
    pid = proc / '123'
    pid.mkdir(parents=True)
    (pid / 'comm').write_text('browser\n')
    (pid / 'exe').symlink_to('/usr/local/bin/browser')
    assert running_applications(proc, self_pid=-1) == [
        DesktopApp('browser', '/usr/local/bin/browser', 'browser', running=True, source='running')]


def test_env_assignment_launcher_is_safely_unwrapped(tmp_path):
    executable = tmp_path / 'browser'
    executable.write_text('#!/bin/sh\n')
    executable.chmod(0o755)
    assert _launcher_executable(f'env MOZ_SANDBOX=1 {executable} %U') == str(executable)
    assert _launcher_executable(f'env -u HOME {executable}') == ''
