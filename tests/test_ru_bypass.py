"""Global .ru exception must have higher priority than all other route modes.

These are configuration checks. Encrypted/hostname-less traffic cannot be
identified by a domain-based rule, and requires live network testing.
"""

import pytest

from app.config_parser import RU_DOMAIN_SUFFIX, RoutingOptions, build_singbox_config

OUTBOUND = {"type": "socks", "tag": "proxy", "server": "proxy.example.org", "server_port": 1080}
RU_ROUTE = {"domain_suffix": [RU_DOMAIN_SUFFIX], "outbound": "direct"}
RU_DNS = {"domain_suffix": [RU_DOMAIN_SUFFIX], "action": "route", "server": "direct-dns"}


@pytest.mark.parametrize("routing_mode", ["all", "only_selected", "all_except_selected"])
@pytest.mark.parametrize("app_mode", ["disabled", "proxy_selected", "direct_selected"])
@pytest.mark.parametrize("dns_mode", ["proxy", "direct", "custom"])
def test_ru_bypass_wins_for_every_routing_app_and_dns_mode(routing_mode, app_mode, dns_mode):
    options = RoutingOptions(
        mode=routing_mode,
        dns_mode=dns_mode,
        custom_dns="1.1.1.1" if dns_mode == "custom" else "",
        domains=["news.ru", "example.com"],
        include_subdomains=False,
        app_mode=app_mode,
        app_process_paths=["/usr/bin/browser"],
        ignore_ru_domains=True,
    )
    config = build_singbox_config(OUTBOUND, options)
    rules = config["route"]["rules"]
    assert rules.count(RU_ROUTE) == 1
    assert config["dns"]["rules"][0] == RU_DNS
    assert sum(server["tag"] == "direct-dns" for server in config["dns"]["servers"]) == 1

    index = rules.index(RU_ROUTE)
    # Safety rules for localhost and the proxy endpoint can precede .ru;
    # they are already DIRECT. Nothing that tunnels or blocks may precede it.
    for rule in rules[:index]:
        assert rule.get("outbound") in {None, "direct"}, rule
    assert not any("process_path" in rule for rule in rules[:index])
    assert not any("process_name" in rule for rule in rules[:index])
    # Catch-all outbounds must never accidentally suppress the exception.
    assert rules[index]["outbound"] == "direct"


@pytest.mark.parametrize("app_mode", ["disabled", "proxy_selected", "direct_selected"])
def test_ru_bypass_is_opt_in(app_mode):
    config = build_singbox_config(OUTBOUND, RoutingOptions(
        app_mode=app_mode, app_process_names=["browser"], ignore_ru_domains=False))
    assert RU_ROUTE not in config["route"]["rules"]
    assert RU_DNS not in config["dns"].get("rules", [])
