"""Auditable starter presets; users can edit every rule before applying."""
from __future__ import annotations

PRESETS: dict[str, tuple[str, str]] = {
    'all': ('Proxy everything', ''),
    'bypass_ru': ('Proxy with .ru bypass', ''),
    'work': ('Work & collaboration', 'github.com\ngithubusercontent.com\nslack.com\nslack-edge.com\nnotion.so\nfigma.com'),
    'video': ('Video streaming', 'youtube.com\nyoutu.be\ngooglevideo.com\nytimg.com\nnetflix.com\nnflxvideo.net'),
    'custom': ('Custom rules', ''),
}


def preset_values(key: str) -> tuple[str, bool, str]:
    if key not in PRESETS:
        raise ValueError('Unknown routing preset')
    if key == 'all':
        return 'all', False, ''
    if key == 'bypass_ru':
        return 'all', True, ''
    if key == 'custom':
        return 'all_except_selected', False, ''
    return 'only_selected', False, PRESETS[key][1]
