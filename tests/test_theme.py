from app.theme import STYLESHEET


def test_theme_is_one_balanced_stylesheet_without_stacked_legacy_rules():
    assert STYLESHEET.count('{') == STYLESHEET.count('}')
    assert '#appModeBtn' in STYLESHEET
    assert '#connectBtn' in STYLESHEET
    assert '#subscriptionCard' in STYLESHEET
    assert STYLESHEET.count('QMainWindow, QWidget#root') == 1
