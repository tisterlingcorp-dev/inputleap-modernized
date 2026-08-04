/*
* InputLeap -- mouse and keyboard sharing utility
* Copyright (C) 2018 Debauchee Open Source Group
*
* This package is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* found in the file LICENSE that should have accompanied this file.
*
* This package is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "LogWindow.h"
#include "ui_LogWindow.h"
#include <QDateTime>

#include <QTimer>
#include <QVBoxLayout>
#include <QLabel>
#include <QFrame>

#define LOGWINDOW_REFRESH_MSECS 100

static const QString s_error_line = QStringLiteral("%1 ERROR: %2\n");
static const QString s_info_line = QStringLiteral("%1 INFO: %2\n");
static const QString s_debug_line = QStringLiteral("%1 DEBUG: %2\n");
static const QString s_text_line = QStringLiteral("%1\n");

static QString getTimeStamp()
{
    QDateTime current = QDateTime::currentDateTime();
    return '[' + current.toString(Qt::ISODate) + ']';
}

LogWindow::LogWindow(QWidget *parent) :
    QDialog(parent),
    ui_{std::make_unique<Ui::LogWindow>()}
{
    // explicitly unset DeleteOnClose so the log window can be show and hidden
    // repeatedly until InputLeap is finished
    setAttribute(Qt::WA_DeleteOnClose, false);
    ui_->setupUi(this);

    setWindowTitle(tr("Registro de atividades — InputLeap"));
    if (auto* rootLayout = qobject_cast<QVBoxLayout*>(layout())) {
        auto* header = new QFrame(this);
        header->setObjectName("logHeader");
        auto* headerLayout = new QVBoxLayout(header);
        headerLayout->setContentsMargins(16, 12, 16, 12);
        headerLayout->setSpacing(2);
        auto* title = new QLabel(tr("Registro de atividades"), header);
        title->setObjectName("logTitle");
        auto* subtitle = new QLabel(tr("Eventos de conexão, transferência e diagnóstico em tempo real."), header);
        subtitle->setObjectName("logSubtitle");
        headerLayout->addWidget(title);
        headerLayout->addWidget(subtitle);
        rootLayout->insertWidget(0, header);
    }
    ui_->m_pButtonClearLog->setText(tr("Limpar registro"));
    ui_->m_pButtonHide->setText(tr("Ocultar"));
    setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QFrame#logHeader { background: #0f172a; border-radius: 10px; }"
        "QLabel#logTitle { color: #f8fafc; font-size: 15px; font-weight: 700; }"
        "QLabel#logSubtitle { color: #94a3b8; }"
        "QPlainTextEdit { background: #0b1220; color: #cbd5e1; border: 1px solid #334155; border-radius: 8px; padding: 10px; selection-background-color: #1d4ed8; font-family: Consolas; font-size: 9pt; }"
        "QPushButton { background: #ffffff; color: #334155; border: 1px solid #b8c3d3; border-radius: 6px; padding: 7px 15px; font-weight: 600; }"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2e3; }"
        "QPushButton#m_pButtonClearLog { background: #2563eb; color: #ffffff; border-color: #2563eb; }"
    );

    // purge old log entries from the log window once 10,000 lines have been reached.
    // This caps the memory use around 40 to 50MB
    ui_->m_pLogOutput->setMaximumBlockCount(10000);

    // Use a timer to flush the buffer every 100 milliseconds
    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &LogWindow::flushBuffer);
    timer->start(LOGWINDOW_REFRESH_MSECS);
}

void LogWindow::startNewInstance()
{
    // put a space between last log output and new instance.
    if (!buffer_.isEmpty())
        appendRaw("");
}

void LogWindow::appendInfo(const QString& text)
{
    buffer_.append(s_info_line.arg(getTimeStamp(),text));
}

void LogWindow::appendDebug(const QString& text)
{
    buffer_.append(s_debug_line.arg(getTimeStamp(),text));
}

void LogWindow::appendError(const QString& text)
{
    buffer_.append(s_error_line.arg(getTimeStamp(),text));
}

void LogWindow::appendRaw(const QString& text)
{
    buffer_.append(s_text_line.arg(text));
}

void LogWindow::flushBuffer()
{
    if (!buffer_.isEmpty()) {
        // Insert the new log content from the buffer
        ui_->m_pLogOutput->appendPlainText(buffer_);
        buffer_.clear();
    }
}

void LogWindow::on_m_pButtonHide_clicked()
{
    hide();
}

void LogWindow::on_m_pButtonClearLog_clicked()
{
    ui_->m_pLogOutput->clear();
}

LogWindow::~LogWindow() = default;
