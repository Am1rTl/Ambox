from app.single_instance import SingleInstanceGuard, notify_running_instance


def test_second_guard_fails_while_first_holds(tmp_path):
    first = SingleInstanceGuard(tmp_path / "app.lock")
    assert first.try_acquire() is True
    try:
        second = SingleInstanceGuard(tmp_path / "app.lock")
        assert second.try_acquire() is False
    finally:
        first.release()


def test_lock_is_reacquirable_after_release(tmp_path):
    first = SingleInstanceGuard(tmp_path / "app.lock")
    assert first.try_acquire() is True
    first.release()
    second = SingleInstanceGuard(tmp_path / "app.lock")
    assert second.try_acquire() is True
    second.release()


def test_notify_without_server_returns_false():
    # No QLocalServer is listening in the test process.
    assert notify_running_instance() is False
