/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2023-2024 InputLeap Developers
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
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

#include "AboutDialog.h"
#include "ui_AboutDialog.h"

#include "common/Version.h"

#include <QPushButton>

AboutDialog::AboutDialog(QWidget* parent, const QString& app_name) :
    QDialog(parent, Qt::WindowTitleHint | Qt::WindowSystemMenuHint),
    ui_{std::make_unique<Ui::AboutDialog>()}
{
    ui_->setupUi(this);
    QString version = QString::fromUtf8(kVersion);
#ifdef INPUTLEAP_REVISION
    const QString revision = QStringLiteral(INPUTLEAP_REVISION);
    if (!revision.isEmpty()) {
        version.append(QStringLiteral("-%1").arg(revision));
    }
#endif
    ui_->m_pLabelAppVersion->setText(version);
    const int scaled_logo_height = sizeHint().width() <= 300 ? 45 : 90;
    const QPixmap scaled_logo = QPixmap(":/res/image/about.png")
                 .scaled(QSize(sizeHint().width(), scaled_logo_height),
                         Qt::KeepAspectRatio, Qt::SmoothTransformation
    );
    ui_->logoLabel->setPixmap(scaled_logo);
    setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QLabel { color: #334155; }"
        "QLabel#logoLabel { background: #ffffff; border: 1px solid #dbe3ee; border-radius: 12px; padding: 16px; }"
        "QLabel#m_pLabelAppVersion { color: #1d4ed8; background: #e8efff; border-radius: 10px; padding: 4px 9px; font-weight: 700; }"
        "QPushButton { background: #2563eb; color: #ffffff; border: none; border-radius: 6px; padding: 8px 20px; font-weight: 700; }"
        "QPushButton:hover { background: #1d4ed8; }"
    );
    const auto buttons = findChildren<QPushButton*>();
    for (auto* button : buttons) {
        button->setText(tr("Fechar"));
        button->setAccessibleName(button->text());
    }
    const QSize minimum = sizeHint();
    setMinimumSize(minimum);
    resize(minimum);
}

AboutDialog::~AboutDialog() = default;
