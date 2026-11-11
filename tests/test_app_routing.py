"""App-only routing must not accidentally tunnel unrelated processes."""
from app.config_parser import RoutingOptions, build_singbox_config

OUTBOUND = {'type': 'socks', 'server': 'vpn.example', 'server_port': 1080, 'tag': 'proxy'}


def _rules(config, key):
    return [rule for rule in config['route']['rules'] if key in rule]


def test_only_selected_apps_has_direct_fallback_even_with_all_domains():
    routing = RoutingOptions(mode='all', dns_mode='proxy', app_mode='proxy_selected',
                             app_process_paths=['/usr/bin/firefox'])
    config = build_singbox_config(OUTBOUND, routing)
    assert config['route']['final'] == 'direct'
    assert _rules(config, 'process_path') == [
        {'process_path': ['/usr/bin/firefox'], 'outbound': 'proxy'}]
    assert config['dns']['final'] == 'direct-dns'


def test_app_mode_ignores_conflicting_domain_modes_and_exceptions():
    routing = RoutingOptions(mode='all_except_selected', domains=['example.org'],
                             ignore_ru_domains=True, app_mode='proxy_selected',
                             app_process_paths=['/opt/browser'])
    config = build_singbox_config(OUTBOUND, routing)
    assert config['route']['final'] == 'direct'
    assert all(rule['outbound'] == 'direct' for rule in _rules(config, 'domain_suffix'))
    assert not _rules(config, 'domain') or all('example.org' not in x.get('domain', [])
                                              for x in _rules(config, 'domain'))


def test_excluding_an_app_forces_non_selected_apps_through_proxy():
    routing = RoutingOptions(mode='only_selected', domains=['example.org'], app_mode='direct_selected',
                             app_process_paths=['/opt/game'])
    config = build_singbox_config(OUTBOUND, routing)
    assert config['route']['final'] == 'proxy'
    assert {'process_path': ['/opt/game'], 'outbound': 'direct'} in config['route']['rules']
    assert not any('example.org' in rule.get('domain_suffix', []) for rule in config['route']['rules'])


def test_tcp_only_proxy_blocks_only_selected_app_udp():
    routing = RoutingOptions(app_mode='proxy_selected', app_process_paths=['/opt/app'])
    config = build_singbox_config({'type':'http','server':'vpn.example', 'server_port':8080}, routing)
    assert config['route']['final'] == 'direct'
    assert {'process_path':['/opt/app'], 'network':['udp'], 'outbound':'block'} in config['route']['rules']
    assert {'network':['udp'], 'outbound':'block'} not in config['route']['rules']


def test_regular_domain_routing_unaffected_when_app_mode_disabled():
    routing = RoutingOptions(mode='all_except_selected', domains=['example.org'], app_mode='disabled')
    config = build_singbox_config(OUTBOUND, routing)
    assert config['route']['final'] == 'proxy'
    assert {'domain_suffix':['example.org'], 'outbound':'direct'} in config['route']['rules']
