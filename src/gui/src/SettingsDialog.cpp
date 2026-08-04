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

#include "SettingsDialog.h"
#include "ui_SettingsDialog.h"

#include "AppLocale.h"
#include "QUtility.h"
#include "AppConfig.h"
#include "EnvironmentProfileController.h"
#include "EnvironmentProfileSelector.h"
#include "EnvironmentProfileUiBinding.h"
#include "ConfigurationAppTarget.h"
#include "ConfigurationExportService.h"
#include "ConfigurationImportPreview.h"
#include "ConfigurationImportService.h"
#include "ConfigurationPackageCodec.h"

#include <QtCore>
#include <QtGui>
#include <QMessageBox>
#include <QFileDialog>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScreen>
#include <QStandardPaths>
#include <QUrl>
#include <QVBoxLayout>
#include <QFrame>
#include <QGroupBox>
#include <QCheckBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFile>
#include <QInputDialog>

#include <openssl/crypto.h>

namespace {
SensitiveBytes takeSensitiveText(QString& text)
{
    QByteArray encoded = text.toUtf8();
    if (!text.isEmpty())
        OPENSSL_cleanse(text.data(), static_cast<size_t>(text.size() * sizeof(QChar)));
    text.clear();
    return SensitiveBytes(std::move(encoded));
}

SensitiveBytes takeSensitiveText(QLineEdit* edit)
{
    QString text = edit->text();
    QByteArray encoded = text.toUtf8();
    const qsizetype length = text.size();
    if (length > 0)
        edit->setText(QString(length, QChar(u'\0')));
    if (!text.isEmpty())
        OPENSSL_cleanse(text.data(), static_cast<size_t>(text.size() * sizeof(QChar)));
    text.clear();
    edit->clear();
    return SensitiveBytes(std::move(encoded));
}

struct SensitivePromptResult {
    bool accepted = false;
    SensitiveBytes value;
};

SensitivePromptResult promptSensitiveText(QWidget* parent, const QString& title,
                                          const QString& label)
{
    QDialog dialog(parent);
    dialog.setWindowTitle(title);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(label, &dialog));
    auto* edit = new QLineEdit(&dialog);
    edit->setEchoMode(QLineEdit::Password);
    layout->addWidget(edit);
    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    edit->setFocus();
    const bool accepted = dialog.exec() == QDialog::Accepted;
    SensitiveBytes value = takeSensitiveText(edit);
    return {accepted, std::move(value)};
}
}

SettingsDialog::SettingsDialog(QWidget* parent, AppConfig& config) :
    SettingsDialog(parent, config, nullptr, false, false)
{
}

SettingsDialog::SettingsDialog(QWidget* parent, AppConfig& config,
                               EnvironmentProfileController* profileController,
                               bool profilesAvailable, bool profilesBusy,
                               bool externalConfig) :
    QDialog(parent, Qt::WindowTitleHint | Qt::WindowSystemMenuHint),
    ui_{std::make_unique<Ui::SettingsDialog>()},
    app_config_(config),
    profile_controller_(profileController)
{
    ui_->setupUi(this);
    if (auto* rootLayout = qobject_cast<QVBoxLayout*>(layout())) {
        auto* header = new QFrame(this);
        header->setObjectName("settingsHeader");
        auto* headerLayout = new QVBoxLayout(header);
        headerLayout->setContentsMargins(18, 13, 18, 13);
        headerLayout->setSpacing(2);
        auto* title = new QLabel(tr("Configurações"), header);
        title->setObjectName("settingsTitle");
        auto* subtitle = new QLabel(tr("Personalize o aplicativo, a rede, a segurança e os registros."), header);
        subtitle->setObjectName("settingsSubtitle");
        headerLayout->addWidget(title);
        headerLayout->addWidget(subtitle);
        rootLayout->insertWidget(0, header);
    }
    setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QScrollArea#settingsScrollArea, QWidget#settingsScrollContent { background: #f5f7fa; border: none; }"
        "QFrame#settingsHeader { background: #0f172a; border-radius: 11px; }"
        "QLabel#settingsTitle { color: #f8fafc; font-size: 16px; font-weight: 700; }"
        "QLabel#settingsSubtitle { color: #94a3b8; }"
        "QGroupBox { background: #ffffff; border: 1px solid #d8dee8; border-radius: 9px; margin-top: 12px; padding: 16px 12px 12px; font-weight: 700; color: #1e293b; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }"
        "QLabel, QCheckBox { color: #334155; }"
        "QLineEdit, QComboBox, QSpinBox { background: #ffffff; border: 1px solid #aab4c3; border-radius: 6px; padding: 6px 8px; min-height: 20px; }"
        "QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #2563eb; }"
        "QPushButton { background: #ffffff; color: #334155; border: 1px solid #aab4c3; border-radius: 6px; padding: 7px 14px; font-weight: 600; }"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2e3; }"
        "QPushButton:default { background: #2563eb; color: #ffffff; border-color: #2563eb; }"
    );

    ui_->m_pGroupGeneral->setTitle(tr("Geral"));
    ui_->m_pGroupNetworking->setTitle(tr("Rede e segurança"));
    ui_->m_pGroupLog->setTitle(tr("Registro"));
    ui_->m_pLabel_20->setText(tr("Porta:"));
    ui_->m_pLabel_21->setText(tr("Endereço:"));
    ui_->m_pLabel_3->setText(tr("Nível do registro:"));
    ui_->m_pCheckBoxLogToFile->setText(tr("Salvar registro em:"));
    ui_->m_pButtonBrowseLog->setText(tr("Navegar..."));
    ui_->m_pComboLogLevel->setItemText(0, tr("Erro"));
    ui_->m_pComboLogLevel->setItemText(1, tr("Aviso"));
    ui_->m_pComboLogLevel->setItemText(2, tr("Nota"));
    ui_->m_pComboLogLevel->setItemText(3, tr("Informação"));
    ui_->m_pComboLogLevel->setItemText(4, tr("Depuração"));
    ui_->m_pComboLogLevel->setItemText(5, tr("Depuração detalhada"));
    ui_->m_pComboLogLevel->setItemText(6, tr("Depuração completa"));
    ui_->m_pLabelElevate->setText(tr("Elevação:"));
    ui_->m_pComboElevate->setItemText(0, tr("Conforme necessário"));
    ui_->m_pComboElevate->setItemText(1, tr("Sempre"));
    ui_->m_pComboElevate->setItemText(2, tr("Nunca"));
    ui_->m_pCheckBoxMinimizeToTray->setText(tr("Minimizar para a bandeja do sistema"));
    ui_->m_pCheckBoxAutoHide->setText(tr("Ocultar ao iniciar"));
    ui_->m_pCheckBoxAutoStart->setText(tr("Iniciar o InputLeap automaticamente"));
    ui_->m_pCheckBoxEnableCrypto->setText(tr("Ativar SSL"));
    ui_->checkbox_require_client_certificate->setText(tr("Exigir certificado do cliente"));

    auto* receiveDirectoryRow = new QWidget(ui_->m_pGroupGeneral);
    auto* receiveDirectoryLayout = new QHBoxLayout(receiveDirectoryRow);
    receiveDirectoryLayout->setContentsMargins(0, 0, 0, 0);
    receiveDirectoryLayout->setSpacing(6);
    receive_directory_edit_ = new QLineEdit(receiveDirectoryRow);
    receive_directory_edit_->setPlaceholderText(tr("Downloads/InputLeap"));
    auto* browseReceiveDirectoryButton = new QPushButton(tr("Navegar..."), receiveDirectoryRow);
    auto* openReceiveDirectoryButton = new QPushButton(tr("Abrir"), receiveDirectoryRow);
    receiveDirectoryLayout->addWidget(receive_directory_edit_);
    receiveDirectoryLayout->addWidget(browseReceiveDirectoryButton);
    receiveDirectoryLayout->addWidget(openReceiveDirectoryButton);
    if (auto* generalLayout = qobject_cast<QFormLayout*>(ui_->m_pGroupGeneral->layout())) {
        generalLayout->addRow(tr("Receber arquivos em:"), receiveDirectoryRow);

        pairing_code_edit_ = new QLineEdit(ui_->m_pGroupGeneral);
        pairing_code_edit_->setObjectName(QStringLiteral("pairingCodeEdit"));
        pairing_code_edit_->setEchoMode(QLineEdit::Password);
        pairing_code_edit_->setPlaceholderText(tr("Opcional: protege as transferências de arquivos"));
        generalLayout->addRow(tr("Código de pareamento:"), pairing_code_edit_);

        auto* trustedPeersRow = new QWidget(ui_->m_pGroupGeneral);
        auto* trustedPeersLayout = new QHBoxLayout(trustedPeersRow);
        trustedPeersLayout->setContentsMargins(0, 0, 0, 0);
        trustedPeersLayout->setSpacing(6);

        const QStringList trustedPeers = app_config_.settings().value("trustedFileTransferPeers").toStringList();
        const int trustedPeerCount = trustedPeers.size();
        auto* trustedPeersLabel = new QLabel(tr("Nenhum"), trustedPeersRow);
        trustedPeersLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto* trustedPeersCombo = new QComboBox(trustedPeersRow);
        trustedPeersCombo->addItems(trustedPeers);
        trustedPeersCombo->setEnabled(trustedPeerCount > 0);
        trustedPeersCombo->setVisible(trustedPeerCount > 0);
        trustedPeersLabel->setVisible(trustedPeerCount == 0);
        auto* removeTrustedPeerButton = new QPushButton(tr("Remover"), trustedPeersRow);
        removeTrustedPeerButton->setEnabled(trustedPeerCount > 0);
        auto* clearTrustedPeersButton = new QPushButton(tr("Limpar"), trustedPeersRow);
        clearTrustedPeersButton->setEnabled(trustedPeerCount > 0);

        trustedPeersLayout->addWidget(trustedPeersLabel, 1);
        trustedPeersLayout->addWidget(trustedPeersCombo, 1);
        trustedPeersLayout->addWidget(removeTrustedPeerButton);
        trustedPeersLayout->addWidget(clearTrustedPeersButton);
        generalLayout->addRow(tr("Computadores confiáveis:"), trustedPeersRow);

        connect(removeTrustedPeerButton, &QPushButton::clicked, this,
                [this, trustedPeersLabel, trustedPeersCombo, removeTrustedPeerButton, clearTrustedPeersButton]() {
            const QString peerToRemove = trustedPeersCombo->currentText();
            if (peerToRemove.isEmpty()) {
                return;
            }

            QStringList updatedTrustedPeers = app_config_.settings().value("trustedFileTransferPeers").toStringList();
            updatedTrustedPeers.removeAll(peerToRemove);
            app_config_.settings().setValue("trustedFileTransferPeers", updatedTrustedPeers);

            trustedPeersCombo->removeItem(trustedPeersCombo->currentIndex());
            const bool hasTrustedPeers = trustedPeersCombo->count() > 0;
            trustedPeersCombo->setEnabled(hasTrustedPeers);
            trustedPeersCombo->setVisible(hasTrustedPeers);
            trustedPeersLabel->setVisible(!hasTrustedPeers);
            removeTrustedPeerButton->setEnabled(hasTrustedPeers);
            clearTrustedPeersButton->setEnabled(hasTrustedPeers);
            QMessageBox::information(this, tr("Computadores confiáveis"), tr("Computador confiável removido: %1").arg(peerToRemove));
        });

        connect(clearTrustedPeersButton, &QPushButton::clicked, this,
                [this, trustedPeersLabel, trustedPeersCombo, removeTrustedPeerButton, clearTrustedPeersButton]() {
            app_config_.settings().remove("trustedFileTransferPeers");
            trustedPeersLabel->setText(tr("Nenhum"));
            trustedPeersLabel->setVisible(true);
            trustedPeersCombo->clear();
            trustedPeersCombo->setEnabled(false);
            trustedPeersCombo->setVisible(false);
            removeTrustedPeerButton->setEnabled(false);
            clearTrustedPeersButton->setEnabled(false);
            QMessageBox::information(this, tr("Computadores confiáveis"), tr("A lista de computadores confiáveis foi limpa."));
        });
    }

    if (auto* rootLayout = qobject_cast<QVBoxLayout*>(layout())) {
        auto* backupGroup = new QGroupBox(tr("Backup e restauração"), this);
        auto* backupLayout = new QVBoxLayout(backupGroup);
        auto* backupDescription = new QLabel(
            tr("Exporte as configurações salvas ou revise um backup antes de importar."),
            backupGroup);
        backupDescription->setWordWrap(true);
        auto* backupButtons = new QHBoxLayout;
        auto* exportButton = new QPushButton(tr("Exportar backup..."), backupGroup);
        import_configuration_button_ = new QPushButton(tr("Importar backup..."), backupGroup);
        exportButton->setObjectName(QStringLiteral("exportConfigurationButton"));
        import_configuration_button_->setObjectName(QStringLiteral("importConfigurationButton"));
        const bool backupAvailable = profileController != nullptr;
        exportButton->setEnabled(backupAvailable);
        import_configuration_button_->setEnabled(
            backupAvailable && profilesAvailable && !profilesBusy && !externalConfig);
        if (!backupAvailable) {
            const QString reason = tr("Os perfis de ambiente não estão disponíveis nesta janela.");
            exportButton->setToolTip(reason);
            import_configuration_button_->setToolTip(reason);
        }
        else if (profilesBusy || externalConfig) {
            import_configuration_button_->setToolTip(externalConfig
                ? tr("A configuração externa está ativa; a importação não pode substituir os perfis.")
                : tr("A importação ficará disponível quando a operação atual terminar."));
        }
        backupButtons->addWidget(exportButton);
        backupButtons->addWidget(import_configuration_button_);
        backupButtons->addStretch(1);
        backupLayout->addWidget(backupDescription);
        backupLayout->addLayout(backupButtons);
        rootLayout->insertWidget(qMax(0, rootLayout->count() - 1), backupGroup);
        connect(exportButton, &QPushButton::clicked, this, &SettingsDialog::exportConfiguration);
        connect(import_configuration_button_, &QPushButton::clicked,
                this, &SettingsDialog::importConfiguration);

        auto* profilesGroup = new QGroupBox(tr("Perfis de ambiente"), this);
        auto* profilesLayout = new QVBoxLayout(profilesGroup);
        environment_profile_selector_ = new EnvironmentProfileSelector(profilesGroup);
        profilesLayout->addWidget(environment_profile_selector_);
        rootLayout->insertWidget(qMax(0, rootLayout->count() - 1), profilesGroup);

        if (profileController) {
            if (externalConfig) {
                environment_profile_selector_->setSwitchEnabled(false,
                    tr("A configuração externa está ativa; perfis de ambiente não podem alterar esse layout nesta versão."));
            }
            environment_profile_binding_ = std::make_unique<EnvironmentProfileUiBinding>(
                *environment_profile_selector_, *profileController,
                [this](const QString& text) {
                    return QMessageBox::question(this, tr("Perfis de ambiente"), text,
                        QMessageBox::Save | QMessageBox::Cancel,
                        QMessageBox::Cancel) == QMessageBox::Save;
                },
                [this](const QString& title, const QString& message, bool warning) {
                    if (warning) QMessageBox::warning(this, title, message);
                    else QMessageBox::information(this, title, message);
                });
            environment_profile_binding_->refresh(profilesAvailable, profilesBusy, externalConfig);
        }
        else {
            environment_profile_selector_->setSwitchEnabled(
                false, tr("Os perfis de ambiente não estão disponíveis nesta janela."));
        }
    }

    if (auto* rootLayout = qobject_cast<QVBoxLayout*>(layout())) {
        auto* scrollArea = new QScrollArea(this);
        scrollArea->setObjectName(QStringLiteral("settingsScrollArea"));
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

        auto* scrollContent = new QWidget(scrollArea);
        scrollContent->setObjectName(QStringLiteral("settingsScrollContent"));
        auto* contentLayout = new QVBoxLayout(scrollContent);
        contentLayout->setContentsMargins(0, 0, 0, 0);
        contentLayout->setSpacing(rootLayout->spacing());

        while (rootLayout->count() > 0) {
            QLayoutItem* item = rootLayout->takeAt(0);
            QWidget* widget = item->widget();
            if (widget == ui_->buttonBox) {
                delete item;
                continue;
            }
            if (widget != nullptr) {
                delete item;
                widget->setParent(scrollContent);
                contentLayout->addWidget(widget);
            }
            else {
                contentLayout->addItem(item);
            }
        }

        scrollArea->setWidget(scrollContent);
        rootLayout->addWidget(scrollArea, 1);
        ui_->buttonBox->setParent(this);
        rootLayout->addWidget(ui_->buttonBox, 0);

        const QScreen* targetScreen = parentWidget() != nullptr
            ? parentWidget()->screen()
            : QGuiApplication::primaryScreen();
        const QSize available = targetScreen != nullptr
            ? targetScreen->availableGeometry().size() - QSize(48, 48)
            : QSize(720, 720);
        const QSize initialSize(
            qMax(320, qMin(720, available.width())),
            qMax(360, qMin(760, available.height())));
        setMinimumSize(qMin(500, initialSize.width()), qMin(420, initialSize.height()));
        resize(initialSize);
    }

    if (auto* okButton = ui_->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setText(tr("Salvar"));
    }
    if (auto* cancelButton = ui_->buttonBox->button(QDialogButtonBox::Cancel)) {
        cancelButton->setText(tr("Cancelar"));
    }

    connect(ui_->buttonBox, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(ui_->buttonBox, &QDialogButtonBox::rejected, this, &SettingsDialog::reject);

    AppLocale locale;
    locale.fillLanguageComboBox(ui_->m_pComboLanguage);

    ui_->m_pLineEditScreenName->setText(app_config_.screenName());
    ui_->m_pSpinBoxPort->setValue(app_config_.port());
    ui_->m_pLineEditInterface->setText(app_config_.networkInterface());
    ui_->m_pComboLogLevel->setCurrentIndex(app_config_.logLevel());
    ui_->m_pCheckBoxLogToFile->setChecked(app_config_.logToFile());
    ui_->m_pLineEditLogFilename->setText(app_config_.logFilename());
    receive_directory_edit_->setText(app_config_.receiveDirectory());
    pairing_code_edit_->setText(app_config_.fileTransferPairingCode());
    setIndexFromItemData(ui_->m_pComboLanguage, app_config_.language());
    ui_->m_pCheckBoxAutoHide->setChecked(app_config_.getAutoHide());
    ui_->m_pCheckBoxAutoStart->setChecked(app_config_.getAutoStart());
    ui_->m_pCheckBoxMinimizeToTray->setChecked(app_config_.getMinimizeToTray());
    ui_->m_pCheckBoxEnableCrypto->setChecked(app_config_.getCryptoEnabled());
    ui_->checkbox_require_client_certificate->setChecked(app_config_.getRequireClientCertificate());

#if defined(Q_OS_WIN)
    ui_->m_pComboElevate->setCurrentIndex(static_cast<int>(app_config_.elevateMode()));
#else
    // elevate checkbox is only useful on ms windows.
    ui_->m_pLabelElevate->hide();
    ui_->m_pComboElevate->hide();
#endif

#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    connect(ui_->m_pCheckBoxLogToFile, &QCheckBox::checkStateChanged, this,
            [this](Qt::CheckState state) { logToFileChanged(state == Qt::Checked); });
#else
    connect(ui_->m_pCheckBoxLogToFile, &QCheckBox::stateChanged, this,
            [this](int state) { logToFileChanged(state == 2); });
#endif
    connect(ui_->m_pButtonBrowseLog, &QPushButton::clicked, this, &SettingsDialog::browseLogClicked);
    connect(browseReceiveDirectoryButton, &QPushButton::clicked, this, &SettingsDialog::browseReceiveDirectoryClicked);
    connect(openReceiveDirectoryButton, &QPushButton::clicked, this, &SettingsDialog::openReceiveDirectoryClicked);
    connect(ui_->m_pComboLanguage, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsDialog::languageChanged);
}

void SettingsDialog::setEnvironmentProfileAvailability(bool available, bool busy, bool externalConfig)
{
    if (environment_profile_binding_) environment_profile_binding_->refresh(available, busy, externalConfig);
    if (import_configuration_button_)
        import_configuration_button_->setEnabled(available && !busy && !externalConfig);
}

void SettingsDialog::accept()
{
    const QString originalScreenName = app_config_.screenName();
    const int originalPort = app_config_.port();
    const QString originalInterface = app_config_.networkInterface();
    const bool originalCryptoEnabled = app_config_.getCryptoEnabled();
    const bool originalRequireClientCertificate =
        app_config_.getRequireClientCertificate();
    const int originalLogLevel = app_config_.logLevel();
    const bool originalLogToFile = app_config_.logToFile();
    const QString originalLogFilename = app_config_.logFilename();
    const QString originalReceiveDirectory = app_config_.receiveDirectory();
    SensitiveBytes originalPairingCode(
        app_config_.fileTransferPairingCode().toUtf8());
    const QString originalLanguage = app_config_.language();
    const ElevateMode originalElevateMode = app_config_.elevateMode();
    const bool originalAutoHide = app_config_.getAutoHide();
    const bool originalAutoStart = app_config_.getAutoStart();
    const bool originalMinimizeToTray = app_config_.getMinimizeToTray();

    app_config_.setScreenName(ui_->m_pLineEditScreenName->text());
    app_config_.setPort(ui_->m_pSpinBoxPort->value());
    app_config_.setNetworkInterface(ui_->m_pLineEditInterface->text());
    app_config_.setCryptoEnabled(ui_->m_pCheckBoxEnableCrypto->isChecked());
    app_config_.setRequireClientCertificate(ui_->checkbox_require_client_certificate->isChecked());
    app_config_.setLogLevel(ui_->m_pComboLogLevel->currentIndex());
    app_config_.setLogToFile(ui_->m_pCheckBoxLogToFile->isChecked());
    app_config_.setLogFilename(ui_->m_pLineEditLogFilename->text());
    app_config_.setReceiveDirectory(receive_directory_edit_->text().trimmed());
    app_config_.setFileTransferPairingCode(pairing_code_edit_->text());
    app_config_.setLanguage(ui_->m_pComboLanguage->itemData(ui_->m_pComboLanguage->currentIndex()).toString());
    app_config_.setElevateMode(static_cast<ElevateMode>(ui_->m_pComboElevate->currentIndex()));
    app_config_.setAutoHide(ui_->m_pCheckBoxAutoHide->isChecked());
    app_config_.setAutoStart(ui_->m_pCheckBoxAutoStart->isChecked());
    app_config_.setMinimizeToTray(ui_->m_pCheckBoxMinimizeToTray->isChecked());
    const auto saveResult = app_config_.saveSettingsWithResult();
    if (saveResult != AppConfig::SaveSettingsResult::Success) {
        app_config_.setScreenName(originalScreenName);
        app_config_.setPort(originalPort);
        app_config_.setNetworkInterface(originalInterface);
        app_config_.setCryptoEnabled(originalCryptoEnabled);
        app_config_.setRequireClientCertificate(originalRequireClientCertificate);
        app_config_.setLogLevel(originalLogLevel);
        app_config_.setLogToFile(originalLogToFile);
        app_config_.setLogFilename(originalLogFilename);
        app_config_.setReceiveDirectory(originalReceiveDirectory);
        QString restoredPairingCode = QString::fromUtf8(originalPairingCode.bytes());
        app_config_.setFileTransferPairingCode(restoredPairingCode);
        takeSensitiveText(restoredPairingCode);
        app_config_.setLanguage(originalLanguage);
        app_config_.setElevateMode(originalElevateMode);
        app_config_.setAutoHide(originalAutoHide);
        app_config_.setAutoStart(originalAutoStart);
        app_config_.setMinimizeToTray(originalMinimizeToTray);
        Q_EMIT requestLanguageChange(originalLanguage);
        Q_EMIT configurationSaveFailed();
        const QString message = saveResult == AppConfig::SaveSettingsResult::ConcurrentModification
            ? tr("As configurações foram alteradas por outra instância do InputLeap. "
                 "Para evitar sobrescrever dados mais novos, nenhuma alteração foi salva. "
                 "Feche e reabra o InputLeap antes de tentar novamente.")
            : tr("Não foi possível salvar as configurações com segurança.");
        QMessageBox::warning(this, tr("Configurações"), message);
        return;
    }
    takeSensitiveText(pairing_code_edit_);
    QDialog::accept();
}

void SettingsDialog::reject()

{
    takeSensitiveText(pairing_code_edit_);
    if (app_config_.language() != ui_->m_pComboLanguage->itemData(ui_->m_pComboLanguage->currentIndex()).toString()) {
        Q_EMIT requestLanguageChange(app_config_.language());
    }
    QDialog::reject();
}

void SettingsDialog::changeEvent(QEvent* event)
{
    if (event != nullptr)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            {
                int logLevelIndex = ui_->m_pComboLogLevel->currentIndex();

                ui_->m_pComboLanguage->blockSignals(true);
                ui_->retranslateUi(this);
                ui_->m_pComboLanguage->blockSignals(false);

                ui_->m_pComboLogLevel->setCurrentIndex(logLevelIndex);
                break;
            }

        default:
            QDialog::changeEvent(event);
        }
    }
}

void SettingsDialog::logToFileChanged(bool checked)
{

    ui_->m_pLineEditLogFilename->setEnabled(checked);
    ui_->m_pButtonBrowseLog->setEnabled(checked);
}

void SettingsDialog::browseLogClicked()
{
    QString fileName = QFileDialog::getSaveFileName(
        this, tr("Salvar arquivo de registro em..."),
        ui_->m_pLineEditLogFilename->text(),
        "Logs (*.log *.txt)");

    if (!fileName.isEmpty())
    {
        ui_->m_pLineEditLogFilename->setText(fileName);
    }
}

void SettingsDialog::browseReceiveDirectoryClicked()
{
    QString directory = QFileDialog::getExistingDirectory(
        this,
        tr("Escolher pasta de recebimento"),
        receive_directory_edit_->text().isEmpty() ? QDir::homePath() : receive_directory_edit_->text());

    if (!directory.isEmpty()) {
        receive_directory_edit_->setText(directory);
    }
}

void SettingsDialog::openReceiveDirectoryClicked()
{
    QString directory = receive_directory_edit_->text().trimmed();
    if (directory.isEmpty()) {
        directory = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
        if (directory.isEmpty()) {
            directory = QDir::homePath();
        }
        directory = QDir(directory).filePath("InputLeap");
    }

    QDir dir(directory);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(dir.absolutePath()))) {
        QMessageBox::warning(this, tr("Abrir pasta de recebimento"), tr("Não foi possível abrir a pasta de recebimento: %1").arg(dir.absolutePath()));
    }
}

void SettingsDialog::exportConfiguration()
{
    const quint64 operationGeneration = beginRuntimeOperation();
    if (!runtimeOperationAuthorized(operationGeneration))
        return;
    if (!profile_controller_) {
        QMessageBox::warning(this, tr("Exportar backup"),
                             tr("Os perfis de ambiente não estão disponíveis."));
        return;
    }
    ConfigurationAppTarget appTarget(app_config_, *profile_controller_);
    const auto snapshot = appTarget.snapshot();
    if (!snapshot) {
        QMessageBox::warning(this, tr("Exportar backup"),
                             tr("Não foi possível validar as configurações salvas."));
        return;
    }

    const QString defaultDirectory = QStandardPaths::writableLocation(
        QStandardPaths::DocumentsLocation);
    const QString suggested = QDir(defaultDirectory).filePath(
        tr("InputLeap-backup-%1.ilconfig").arg(
            QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))));
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Exportar backup"), suggested,
        tr("Backup do InputLeap (*.ilconfig)"));
    if (!runtimeOperationAuthorized(operationGeneration))
        return;
    if (path.isEmpty())
        return;

    QDialog optionsDialog(this);
    optionsDialog.setWindowTitle(tr("Proteção do backup"));
    auto* optionsLayout = new QVBoxLayout(&optionsDialog);
    auto* includeSensitive = new QCheckBox(
        tr("Incluir o código de pareamento persistente (criptografado)"), &optionsDialog);
    const bool sensitiveAvailable = app_config_.sensitiveSettingsAvailable() &&
                                    !app_config_.fileTransferPairingCode().isEmpty();
    includeSensitive->setEnabled(sensitiveAvailable);
    if (!sensitiveAvailable)
        includeSensitive->setToolTip(tr("Nenhum código de pareamento seguro está disponível."));
    auto* password = new QLineEdit(&optionsDialog);
    auto* confirmation = new QLineEdit(&optionsDialog);
    password->setEchoMode(QLineEdit::Password);
    confirmation->setEchoMode(QLineEdit::Password);
    password->setEnabled(false);
    confirmation->setEnabled(false);
    auto* form = new QFormLayout;
    form->addRow(tr("Senha do backup:"), password);
    form->addRow(tr("Confirmar senha:"), confirmation);
    optionsLayout->addWidget(includeSensitive);
    optionsLayout->addLayout(form);
    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &optionsDialog);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Continuar"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancelar"));
    optionsLayout->addWidget(buttons);
    connect(includeSensitive, &QCheckBox::toggled, password, &QWidget::setEnabled);
    connect(includeSensitive, &QCheckBox::toggled, confirmation, &QWidget::setEnabled);
    connect(buttons, &QDialogButtonBox::accepted, &optionsDialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &optionsDialog, &QDialog::reject);
    const int optionsResult = optionsDialog.exec();
    if (!runtimeOperationAuthorized(operationGeneration)) {
        takeSensitiveText(password);
        takeSensitiveText(confirmation);
        return;
    }
    if (optionsResult != QDialog::Accepted) {
        takeSensitiveText(password);
        takeSensitiveText(confirmation);
        return;
    }
    SensitiveBytes exportPassword = takeSensitiveText(password);
    SensitiveBytes exportConfirmation = takeSensitiveText(confirmation);
    const bool exportPasswordValid = !includeSensitive->isChecked() ||
        (!exportPassword.isEmpty() &&
         exportPassword.securelyEquals(exportConfirmation.bytes()));
    exportConfirmation.clear();
    if (!exportPasswordValid) {
        exportPassword.clear();
        QMessageBox::warning(this, tr("Exportar backup"),
                             tr("Informe e confirme a mesma senha para proteger o código de pareamento."));
        return;
    }
    if (!includeSensitive->isChecked())
        exportPassword.clear();

    ConfigurationExportService::Options exportOptions;
    exportOptions.includeSensitive = includeSensitive->isChecked();
    exportOptions.password = exportOptions.includeSensitive ? &exportPassword : nullptr;
    const auto readPairingCode = appTarget.target().readPairingCode;
    if (!runtimeOperationAuthorized(operationGeneration)) {
        exportPassword.clear();
        return;
    }
    const auto package = ConfigurationExportService::build(
        *snapshot, exportOptions,
        [this, operationGeneration, readPairingCode] {
            ConfigurationExportService::SensitiveData data;
            if (!runtimeOperationAuthorized(operationGeneration))
                return data;
            auto state = readPairingCode();
            if (!state.readable)
                return data;
            data.readable = true;
            data.pairingCode = std::move(state.value);
            return data;
        });
    bool written = false;
    if (runtimeOperationAuthorized(operationGeneration) &&
        package.error == ConfigurationExportService::Error::None && package.package) {
        written = ConfigurationExportService::writeAtomically(path, *package.package) ==
                  ConfigurationExportService::Error::None;
    }
    exportPassword.clear();
    if (!runtimeOperationAuthorized(operationGeneration))
        return;
    if (!written) {
        QMessageBox::warning(this, tr("Exportar backup"),
                             tr("Não foi possível criar o backup com segurança."));
        return;
    }
    QMessageBox::information(this, tr("Exportar backup"),
                             tr("Backup criado com sucesso em:\n%1").arg(
                                 QDir::toNativeSeparators(path)));
}

void SettingsDialog::importConfiguration()
{
    const quint64 operationGeneration = beginRuntimeOperation();
    if (!runtimeOperationAuthorized(operationGeneration))
        return;
    if (!profile_controller_)
        return;
    const QString path = import_file_picker_override_
        ? import_file_picker_override_()
        : QFileDialog::getOpenFileName(
              this, tr("Importar backup"),
              QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
              tr("Backup do InputLeap (*.ilconfig)"));
    if (!runtimeOperationAuthorized(operationGeneration))
        return;
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > ConfigurationPackageCodec::MaxPackageBytes) {
        QMessageBox::warning(this, tr("Importar backup"), tr("O arquivo de backup é inválido ou muito grande."));
        return;
    }
    const QByteArray bytes = file.read(ConfigurationPackageCodec::MaxPackageBytes + 1);
    if (bytes.size() > ConfigurationPackageCodec::MaxPackageBytes) {
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("O arquivo de backup é inválido ou muito grande."));
        return;
    }
    ConfigurationAppTarget appTarget(app_config_, *profile_controller_);
    const auto current = appTarget.snapshot();
    if (!current) {
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("Não foi possível validar a configuração atual."));
        return;
    }

    SensitiveBytes importPassword;
    auto previewResult = ConfigurationImportPreview::create(bytes, *current, importPassword);
    if (previewResult.error == ConfigurationImportPreview::Error::PasswordRequired) {
        auto prompt = promptSensitiveText(
            this, tr("Backup protegido"), tr("Senha para abrir este arquivo:"));
        importPassword = std::move(prompt.value);
        if (!runtimeOperationAuthorized(operationGeneration)) {
            importPassword.clear();
            return;
        }
        if (!prompt.accepted)
            return;
        previewResult = ConfigurationImportPreview::create(bytes, *current, importPassword);
    }
    if (previewResult.error != ConfigurationImportPreview::Error::None || !previewResult.preview) {
        importPassword.clear();
        previewResult.preview.reset();
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("Não foi possível autenticar ou validar este backup."));
        return;
    }

    importPassword.clear();
    if (previewResult.preview->candidate.sensitive)
        previewResult.preview->candidate.sensitive.reset();

    const auto& summary = previewResult.preview->summary;
    QString pairingAction;
    switch (summary.pairingCodeAction) {
    case ConfigurationImportPreview::Summary::PairingCodeAction::Set:
        pairingAction = tr("substituir pelo valor autenticado e criptografado");
        break;
    case ConfigurationImportPreview::Summary::PairingCodeAction::Clear:
        pairingAction = tr("remover o código atual");
        break;
    case ConfigurationImportPreview::Summary::PairingCodeAction::Preserve:
        pairingAction = tr("preservar o código atual");
        break;
    }
    QString summaryText = tr(
        "Alterações encontradas:\n"
        "• Integridade do pacote: %1\n"
        "• Preferências: %2\n"
        "• Perfis de ambiente: %3 de %4\n"
        "• Referências de dispositivos: %5\n"
        "• Código de pareamento: %6")
        .arg(summary.authenticated
                 ? tr("autenticada por senha")
                 : tr("NÃO autenticada — alterações no arquivo não podem ser detectadas"))
        .arg(summary.preferenceChanges)
        .arg(summary.profileChanges)
        .arg(summary.profileCount)
        .arg(summary.deviceReferences)
        .arg(pairingAction);
    const auto reviewDecision = QMessageBox::question(
        this, tr("Revisar importação"),
        summaryText + tr("\n\nImportar estas configurações? Um backup automático será criado antes."),
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (!runtimeOperationAuthorized(operationGeneration)) {
        previewResult.preview.reset();
        return;
    }
    if (reviewDecision != QMessageBox::Yes) {
        return;
    }
    bool authorizeUnauthenticatedImport = false;
    if (!summary.authenticated) {
        authorizeUnauthenticatedImport = QMessageBox::warning(
            this, tr("Arquivo sem autenticação"),
            tr("Este arquivo público não possui autenticação criptográfica e pode ter sido "
               "alterado por terceiros. Continue somente se você confia na origem e conferiu "
               "as alterações mostradas. Deseja continuar?"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) == QMessageBox::Yes;
        if (!runtimeOperationAuthorized(operationGeneration)) {
            previewResult.preview.reset();
            return;
        }
        if (!authorizeUnauthenticatedImport)
            return;
    }

    bool authorizeDowngrade = false;
    if (summary.weakensTransportSecurity) {
        authorizeDowngrade = QMessageBox::warning(
            this, tr("Redução de proteção"),
            tr("Este backup desativará o TLS ou deixará de exigir certificado do cliente. "
               "Isso reduz a proteção da conexão. Deseja autorizar explicitamente esta alteração?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) == QMessageBox::Yes;
        if (!runtimeOperationAuthorized(operationGeneration)) {
            previewResult.preview.reset();
            return;
        }
        if (!authorizeDowngrade) {
            return;
        }
    }

    QDialog credentialsDialog(this);
    credentialsDialog.setWindowTitle(tr("Senhas da importação"));
    auto* credentialsLayout = new QVBoxLayout(&credentialsDialog);
    auto* credentialsForm = new QFormLayout;
    auto* reopenPasswordEdit = new QLineEdit(&credentialsDialog);
    auto* backupPasswordEdit = new QLineEdit(&credentialsDialog);
    auto* backupConfirmationEdit = new QLineEdit(&credentialsDialog);
    reopenPasswordEdit->setEchoMode(QLineEdit::Password);
    backupPasswordEdit->setEchoMode(QLineEdit::Password);
    backupConfirmationEdit->setEchoMode(QLineEdit::Password);
    if (summary.authenticated)
        credentialsForm->addRow(tr("Senha para reabrir o arquivo:"), reopenPasswordEdit);
    credentialsForm->addRow(tr("Nova senha do backup automático:"), backupPasswordEdit);
    credentialsForm->addRow(tr("Confirmar nova senha:"), backupConfirmationEdit);
    credentialsLayout->addLayout(credentialsForm);
    auto* credentialsButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &credentialsDialog);
    credentialsButtons->button(QDialogButtonBox::Ok)->setText(tr("Continuar"));
    credentialsButtons->button(QDialogButtonBox::Cancel)->setText(tr("Cancelar"));
    credentialsLayout->addWidget(credentialsButtons);
    connect(credentialsButtons, &QDialogButtonBox::accepted,
            &credentialsDialog, &QDialog::accept);
    connect(credentialsButtons, &QDialogButtonBox::rejected,
            &credentialsDialog, &QDialog::reject);
    const int credentialsResult = credentialsDialog.exec();
    if (!runtimeOperationAuthorized(operationGeneration)) {
        takeSensitiveText(reopenPasswordEdit);
        takeSensitiveText(backupPasswordEdit);
        takeSensitiveText(backupConfirmationEdit);
        previewResult.preview.reset();
        return;
    }
    if (credentialsResult != QDialog::Accepted) {
        takeSensitiveText(reopenPasswordEdit);
        takeSensitiveText(backupPasswordEdit);
        takeSensitiveText(backupConfirmationEdit);
        previewResult.preview.reset();
        return;
    }

    SensitiveBytes reopenPassword = takeSensitiveText(reopenPasswordEdit);
    SensitiveBytes backupPassword = takeSensitiveText(backupPasswordEdit);
    SensitiveBytes backupConfirmation = takeSensitiveText(backupConfirmationEdit);
    const bool backupPasswordsMatch =
        backupPassword.securelyEquals(backupConfirmation.bytes());
    backupConfirmation.clear();
    if (backupPassword.isEmpty() || !backupPasswordsMatch ||
        (summary.authenticated && reopenPassword.isEmpty())) {
        reopenPassword.clear();
        backupPassword.clear();
        previewResult.preview.reset();
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("Preencha as senhas solicitadas e confirme corretamente a nova senha."));
        return;
    }
    const bool reusesImportPassword = summary.authenticated &&
        backupPassword.securelyEquals(reopenPassword.bytes());
    if (reusesImportPassword) {
        reopenPassword.clear();
        backupPassword.clear();
        previewResult.preview.reset();
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("Use uma senha diferente da senha usada para abrir o arquivo."));
        return;
    }
    if (summary.authenticated) {
        auto reopenedPreview = ConfigurationImportPreview::create(
            bytes, *current, reopenPassword);
        reopenPassword.clear();
        if (reopenedPreview.error != ConfigurationImportPreview::Error::None ||
            !reopenedPreview.preview) {
            backupPassword.clear();
            previewResult.preview.reset();
            QMessageBox::warning(this, tr("Importar backup"),
                                 tr("Não foi possível reautenticar este backup."));
            return;
        }
        previewResult = std::move(reopenedPreview);
    } else {
        reopenPassword.clear();
    }
    if (!runtimeOperationAuthorized(operationGeneration)) {
        backupPassword.clear();
        previewResult.preview.reset();
        return;
    }
    QString backupDirectory = import_backup_directory_override_.isEmpty()
        ? QDir(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation))
              .filePath(QStringLiteral("backups"))
        : import_backup_directory_override_;
    if (!QDir().mkpath(backupDirectory)) {
        backupPassword.clear();
        previewResult.preview.reset();
        QMessageBox::warning(this, tr("Importar backup"),
                             tr("Não foi possível preparar a pasta do backup automático."));
        return;
    }
    const QString automaticBackup = QDir(backupDirectory).filePath(
        QStringLiteral("before-import-%1-%2.ilconfig")
            .arg(QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz")),
                 QUuid::createUuid().toString(QUuid::WithoutBraces)));
    const auto& previousPreferences = current->preferences;
    const auto& importedPreferences = previewResult.preview->candidate.snapshot.preferences;
    const bool coreRestartRequired =
        previousPreferences.port() != importedPreferences.port() ||
        previousPreferences.logLevel() != importedPreferences.logLevel() ||
        previousPreferences.cryptoEnabled() != importedPreferences.cryptoEnabled() ||
        previousPreferences.requireClientCertificate() !=
            importedPreferences.requireClientCertificate();
    if (!runtimeOperationAuthorized(operationGeneration)) {
        backupPassword.clear();
        previewResult.preview.reset();
        return;
    }
    const auto result = ConfigurationImportService::apply(
        *previewResult.preview, *current, automaticBackup,
        ConfigurationImportService::Options{
            &backupPassword, authorizeDowngrade, authorizeUnauthenticatedImport},
        appTarget.target());
    if (!runtimeOperationAuthorized(operationGeneration)) {
        backupPassword.clear();
        previewResult.preview.reset();
        return;
    }
    if (result != ConfigurationImportService::Error::None) {
        backupPassword.clear();
        previewResult.preview.reset();
        QMessageBox::warning(this, tr("Importar backup"),
                             result == ConfigurationImportService::Error::SecurityDowngradeRequiresConsent
                                 ? tr("A redução de proteção não foi autorizada.")
                                 : tr("A importação não foi concluída. A configuração anterior foi preservada ou o estado foi marcado como indeterminado."));
        return;
    }

    refreshPortableFields();
    environment_profile_selector_->setActiveKind(profile_controller_->activeKind());
    backupPassword.clear();
    importPassword.clear();
    previewResult.preview.reset();
    Q_EMIT configurationImported();
    if (coreRestartRequired) {
        const auto restart = QMessageBox::question(
            this, tr("Importação concluída"),
            tr("Configurações importadas e verificadas. Backup anterior:\n%1\n\n"
               "Uma configuração usada pelo núcleo de conexão foi alterada. "
               "Reiniciar a conexão agora? Se escolher Não, a alteração entrará em vigor "
               "na próxima reconexão.")
                .arg(QDir::toNativeSeparators(automaticBackup)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (restart == QMessageBox::Yes)
            Q_EMIT requestCoreRestart();
        return;
    }
    QMessageBox::information(this, tr("Importar backup"),
                             tr("Configurações importadas e verificadas. Backup anterior:\n%1")
                                 .arg(QDir::toNativeSeparators(automaticBackup)));
}

void SettingsDialog::refreshPortableFields()
{
    ui_->m_pSpinBoxPort->setValue(app_config_.port());
    ui_->m_pComboLogLevel->setCurrentIndex(app_config_.logLevel());
    setIndexFromItemData(ui_->m_pComboLanguage, app_config_.language());
    ui_->m_pCheckBoxEnableCrypto->setChecked(app_config_.getCryptoEnabled());
    ui_->checkbox_require_client_certificate->setChecked(app_config_.getRequireClientCertificate());
    ui_->m_pCheckBoxAutoHide->setChecked(app_config_.getAutoHide());
    ui_->m_pCheckBoxAutoStart->setChecked(app_config_.getAutoStart());
    ui_->m_pCheckBoxMinimizeToTray->setChecked(app_config_.getMinimizeToTray());
    takeSensitiveText(pairing_code_edit_);
    pairing_code_edit_->setText(app_config_.fileTransferPairingCode());
    Q_EMIT requestLanguageChange(app_config_.language());
}

void SettingsDialog::languageChanged(int index)
{
    Q_EMIT requestLanguageChange(ui_->m_pComboLanguage->itemData(index).toString());
}

quint64 SettingsDialog::beginRuntimeOperation() const noexcept
{
    return runtime_operations_authorized_ ? runtime_operation_generation_ : 0;
}

bool SettingsDialog::runtimeOperationAuthorized(quint64 generation) const noexcept
{
    return generation != 0 && runtime_operations_authorized_ &&
           generation == runtime_operation_generation_;
}

void SettingsDialog::invalidateRuntimeOperations()
{
    if (!runtime_operations_authorized_)
        return;
    runtime_operations_authorized_ = false;
    ++runtime_operation_generation_;

    const auto sensitiveEdits = findChildren<QLineEdit*>();
    for (QLineEdit* edit : sensitiveEdits) {
        if (edit && edit->echoMode() != QLineEdit::Normal)
            takeSensitiveText(edit);
    }
    const auto childDialogs = findChildren<QDialog*>();
    for (QDialog* dialog : childDialogs) {
        if (dialog)
            dialog->reject();
    }
    QDialog::reject();
}

SettingsDialog::~SettingsDialog()
{
    takeSensitiveText(pairing_code_edit_);
}
