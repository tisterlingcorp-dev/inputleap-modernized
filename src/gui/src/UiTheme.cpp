/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "UiTheme.h"

#include <QApplication>
#include <QPalette>
#include <QStyleFactory>

void UiTheme::apply(QApplication& app)
{
    app.setStyle(QStyleFactory::create("Fusion"));

    QPalette palette;
    palette.setColor(QPalette::Window, QColor("#f5f7fa"));
    palette.setColor(QPalette::WindowText, QColor("#1f2937"));
    palette.setColor(QPalette::Base, QColor("#ffffff"));
    palette.setColor(QPalette::AlternateBase, QColor("#eef2f7"));
    palette.setColor(QPalette::Text, QColor("#1f2937"));
    palette.setColor(QPalette::Button, QColor("#ffffff"));
    palette.setColor(QPalette::ButtonText, QColor("#1f2937"));
    palette.setColor(QPalette::Highlight, QColor("#2563eb"));
    palette.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    palette.setColor(QPalette::PlaceholderText, QColor("#7a8491"));
    app.setPalette(palette);

    app.setStyleSheet(
        "QMainWindow, QDialog, QWizard, QWidget#centralwidget { background: #f5f7fa; }"
        "QLabel { color: #1f2937; }"
        "QLabel[muted=\"true\"] { color: #64748b; }"
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d8dee8;"
        "  border-radius: 8px;"
        "  margin-top: 11px;"
        "  padding: 14px 12px 12px 12px;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  left: 10px;"
        "  padding: 0 6px;"
        "  color: #172033;"
        "  font-weight: 700;"
        "}"
        "QTabWidget::pane {"
        "  border: 1px solid #d8dee8;"
        "  background: #ffffff;"
        "  border-radius: 6px;"
        "}"
        "QTabBar::tab {"
        "  background: #eef2f7;"
        "  border: 1px solid #d8dee8;"
        "  border-bottom: none;"
        "  padding: 7px 14px;"
        "  margin-right: 2px;"
        "}"
        "QTabBar::tab:selected { background: #ffffff; color: #1d4ed8; font-weight: 600; }"
        "QLineEdit, QComboBox, QSpinBox, QListWidget, QTextEdit, QPlainTextEdit {"
        "  background: #ffffff;"
        "  border: 1px solid #b9c2d0;"
        "  border-radius: 4px;"
        "  padding: 4px 6px;"
        "  selection-background-color: #bfdbfe;"
        "}"
        "QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QListWidget:focus, QTextEdit:focus, QPlainTextEdit:focus {"
        "  border: 1px solid #2563eb;"
        "}"
        "QPushButton {"
        "  background: #ffffff;"
        "  border: 1px solid #b9c2d0;"
        "  border-radius: 4px;"
        "  padding: 5px 14px;"
        "  min-height: 24px;"
        "}"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2f7; }"
        "QPushButton:pressed { background: #dbeafe; }"
        "QPushButton:disabled { color: #7a8491; background: #e7ebf0; }"
        "QPushButton:default { background: #2563eb; color: #ffffff; border-color: #1d4ed8; font-weight: 600; }"
        "QCheckBox, QRadioButton { color: #1f2937; spacing: 7px; }"
        "QMenuBar { background: #f5f7fa; color: #111827; }"
        "QMenuBar::item:selected, QMenu::item:selected { background: #dbeafe; color: #111827; }"
        "QMenu { background: #ffffff; border: 1px solid #d8dee8; padding: 4px; }"
        "QToolTip { background: #111827; color: #ffffff; border: none; padding: 5px 7px; }"
    );
}
