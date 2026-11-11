"""One cohesive compact Qt stylesheet, without stacked ad-hoc overrides.

All palette values are here so pages, subscriptions and application rows share
one visual language. Qt does not implement browser CSS; rules only use Qt QSS.
"""
STYLESHEET = """
QMainWindow, QWidget#root {
    background-color: #0c121b;
}
QWidget {
    color: #e6edf4;
    font-family: "Inter", "Noto Sans", "DejaVu Sans", sans-serif;
    font-size: 13px;
}
QFrame#phoneShell, QStackedWidget#contentStack {
    background-color: #0c121b;
    border: none;
}
QPushButton#headerMenuBtn {
    background: transparent; border: 1px solid transparent;
    border-radius: 8px; padding: 3px; min-height: 0px;
}
QPushButton#headerMenuBtn:hover { background: #1d303d; border-color: #304f5a; }
QPushButton#headerMenuBtn::menu-indicator { image: none; width: 0px; }
QFrame#headerCard {
    background-color: #0c121b;
    border: none;
    border-bottom: 1px solid #253241;
}
QLabel#panelTitle { font-size: 19px; font-weight: 800; color: #f3fafc; }
QLabel#brandHint { color: #8ea0b1; font-size: 11px; }
QLabel#sectionTitle { font-size: 17px; font-weight: 700; color: #f4f8fb; }
QLabel#fieldLabel { color: #a5b7c6; font-size: 11px; font-weight: 700; }
QLabel#quickProfileTitle { color: #a5b7c6; font-weight: 600; }
QLabel#subtitle, QLabel#softHint, QLabel#hint, QLabel#emptyState {
    color: #98a9ba;
    font-size: 12px;
}
QLabel#emptyState { padding: 18px; }
QLabel#statusLabel { font-size: 17px; font-weight: 700; color: #f3f9fd; }
QLabel#statusDot { font-size: 17px; }
QLabel#trafficRate { color: #7ce7c9; font-weight: 700; }
QLabel#subscriptionName { color: #f3f8fc; font-size: 14px; font-weight: 700; }
QLabel#diagnosticSummary { color: #c7f3e6; font-weight: 600; }
QLabel#appModeHint { color: #b6c6d3; font-size: 12px; }
QFrame#statusCard, QFrame#quickProfileCard, QFrame#metricCard,
QFrame#subCard, QFrame#subscriptionCard, QFrame#warningCard {
    background-color: #151f2b;
    border: 1px solid #29394a;
    border-radius: 14px;
}
QFrame#warningCard { border-color: #835f3a; background: #28231e; }
QFrame#appNotice { border: 1px solid #32576a; border-radius: 10px; background: #162a34; }
QPushButton {
    background-color: #202d3b;
    border: 1px solid #35465a;
    border-radius: 10px;
    color: #e1ecf5;
    min-height: 26px;
    padding: 5px 11px;
    font-weight: 600;
}
QPushButton:hover { background-color: #293949; border-color: #567184; }
QPushButton:pressed { background-color: #17242f; }
QPushButton:disabled { color: #697c8e; background: #19232e; border-color: #2a3745; }
QPushButton#primaryAction, QPushButton#connectBtn {
    background-color: #24bfa7;
    color: #061a22;
    border: 1px solid #24bfa7;
    font-weight: 800;
}
QPushButton#primaryAction:hover, QPushButton#connectBtn:hover {
    background-color: #55d9bd; border-color: #55d9bd;
}
QPushButton#connectBtn { border-radius: 11px; font-size: 15px; min-height: 0px; padding: 7px 12px; }
QPushButton#connectBtn[vpnState="connected"] { background: #283c42; color: #76e0c4; border-color: #38766d; }
QPushButton#connectBtn[vpnState="connected"]:hover { background: #34504e; }
QPushButton#sourceTab, QPushButton#appModeBtn { border-color: #2a3c4e; background: #18232f; }
QPushButton#sourceTab:checked, QPushButton#appModeBtn:checked {
    background-color: #204e50; border-color: #43ab9d; color: #a6ffe9;
}
/* A 44px navigation rail, with genuinely 34px buttons at 380px width. */
QPushButton#navBtn {
    background: transparent;
    border: 0; border-radius: 8px;
    color: #91aabd;
    font-size: 11px; font-weight: 650;
    padding: 3px 4px; min-height: 0px;
}
QPushButton#navBtn::menu-indicator { image: none; width: 0px; }
QPushButton#navBtn:hover { background: #253846; color: #e8f7f2; }
QPushButton#navBtn:checked { background: #205046; color: #b1ffe8; }
QFrame#bottomNav {
    background: #141f2a;
    border: 1px solid #29394a;
    border-radius: 12px;
}
QPushButton#quickLink {
    background: #141f2a; border: 1px solid #273c49;
    color: #add9d3; text-align: left;
    font-size: 12px; font-weight: 600;
    padding: 4px 12px; min-height: 0px;
}
QPushButton#quickLink:hover { background: #1c303a; border-color: #397467; }
QPushButton#inlineHelpBtn {
    background: transparent; border: none; min-height: 0px;
    font-size: 11px; text-align: left; color: #8aa9b6;
    padding: 3px 0;
}
QPushButton#inlineHelpBtn:hover { color: #a6ebd5; }
QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit, QAbstractItemView {
    background-color: #121b26;
    color: #e4edf5;
    border: 1px solid #2e4052;
    border-radius: 10px;
    selection-background-color: #286a62;
    selection-color: #f4fffd;
}
QLineEdit, QComboBox, QSpinBox { min-height: 28px; padding: 5px 8px; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {
    border-color: #4bcbb2;
}
QComboBox::drop-down { border: none; width: 23px; }
QComboBox QAbstractItemView {
    border: 1px solid #324657;
    background: #16222e;
    outline: none;
    selection-background-color: #26554f;
}
QListWidget#profiles, QListWidget#applications {
    background: #131d28; border: 1px solid #283a4b;
    border-radius: 12px; outline: none;
}
QListWidget#profiles::item, QListWidget#applications::item {
    padding: 8px 10px; border-bottom: 1px solid #233141;
}
QListWidget#profiles::item:hover, QListWidget#applications::item:hover {
    background-color: #1b2a38;
}
QListWidget#profiles::item:selected, QListWidget#applications::item:selected {
    color: #e9fff9; background-color: #21443f; border-radius: 8px;
}
QListWidget#applications::indicator {
    width: 18px; height: 18px;
    border: 1px solid #526879; border-radius: 5px; background: #0f1a24;
}
QListWidget#applications::indicator:checked { background: #32c4aa; border: 1px solid #32c4aa; }
QCheckBox { spacing: 7px; color: #cbd8e2; }
QCheckBox#ruBypassToggle {
    background-color: #15272f;
    border: 1px solid #2f595a;
    border-radius: 10px;
    color: #d4f1ed;
    padding: 7px 11px;
    font-weight: 600;
}
QCheckBox#ruBypassToggle:hover {
    border-color: #49a99a;
    background-color: #193940;
}
QCheckBox::indicator { width: 18px; height: 18px; }
QCheckBox::indicator:unchecked { background: #111a25; border: 1px solid #526879; border-radius: 5px; }
QCheckBox::indicator:checked { background: #32c4aa; border: 1px solid #32c4aa; border-radius: 5px; }
QProgressBar#subscriptionProgress {
    border: none; border-radius: 3px; background-color: #293746;
}
QProgressBar#subscriptionProgress::chunk { background: #37c7a9; border-radius: 3px; }
QScrollArea { border: none; background: #0c121b; }
QWidget#settingsBody, QWidget#subscriptionHost, QWidget#overviewBody {
    background-color: #0c121b;
}
QScrollArea#subscriptionScroll { background: #0c121b; }
QScrollBar:vertical { width: 7px; background: #0c121b; margin: 3px 0; }
QScrollBar:horizontal { height: 6px; background: #0c121b; margin: 0; }
QScrollBar::handle:horizontal { background: #34465a; min-width: 24px; border-radius: 3px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::handle:vertical { background: #34465a; min-height: 25px; border-radius: 3px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QPlainTextEdit#logs { font-family: "DejaVu Sans Mono", monospace; font-size: 11px; padding: 8px; }
QMenu { background: #1a2735; color: #e5edf4; border: 1px solid #324657; padding: 6px; }
QMenu::item { padding: 8px 18px; border-radius: 6px; }
QMenu::item:selected { background: #265d56; }
QToolTip { background: #243342; color: #f5fbff; border: 1px solid #506578; padding: 4px; }
"""
