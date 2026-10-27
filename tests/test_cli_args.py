from main import _parse_args


def test_tray_flag():
    assert _parse_args([]).tray is False
    assert _parse_args(["--tray"]).tray is True


def test_debug_and_foreground_flags():
    args = _parse_args(["-d", "-f"])
    assert args.debug is True
    assert args.foreground is True


def test_optional_link_argument():
    assert _parse_args([]).link is None
    assert _parse_args(["happ://add/https://example.com/sub"]).link == "happ://add/https://example.com/sub"
