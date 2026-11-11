"""Prevent manual imports and provider-managed nodes from being mixed."""
import pytest

from app.config_parser import Profile
from app.profile_sources import profile_indices_for_source
from app.subscriptions import valid_subscription_link


def _profile(name: str, subscription_id: str | None = None) -> Profile:
    return Profile(name=name, outbound={'type': 'direct'}, subscription_id=subscription_id)


def test_source_tabs_are_disjoint_and_do_not_change_storage_order():
    profiles = [_profile('Manual A'), _profile('Provider A', 'provider-one'),
                _profile('Manual B'), _profile('Provider B', 'provider-two'),
                _profile('Provider C', 'provider-one')]
    assert profile_indices_for_source(profiles, 'manual') == [0, 2]
    assert profile_indices_for_source(profiles, 'subscriptions') == [1, 3, 4]
    assert profile_indices_for_source(profiles, 'subscriptions', 'provider-one') == [1, 4]
    assert profile_indices_for_source(profiles, 'subscriptions', 'provider-two') == [3]
    assert profile_indices_for_source(profiles, 'subscriptions', 'missing') == []
    assert profile_indices_for_source(profiles, 'manual', 'provider-one') == [0, 2]
    assert [p.name for p in profiles] == [
        'Manual A', 'Provider A', 'Manual B', 'Provider B', 'Provider C'
    ]


def test_source_filter_rejects_unknown_group():
    with pytest.raises(ValueError, match='Unknown profile source'):
        profile_indices_for_source([], 'all')


@pytest.mark.parametrize(('link', 'expected'), [
    ('https://provider.example/sub?token=hello', True),
    ('http://localhost:4444/sub', True),
    ('happ://add/https://provider.example/sub', True),
    ('happ://', False),
    ('https:///missing-host', False),
    ('file:///tmp/secrets.json', False),
    ('vless://some-credentials@host:443', False),
    ('', False),
    ('not a link', False),
])
def test_add_subscription_only_accepts_remote_source_urls(link, expected):
    assert valid_subscription_link(link) is expected
