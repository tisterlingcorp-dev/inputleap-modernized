#include "SettingsDialog.h"

#include "AppConfig.h"
#include "ConfigurationAppTarget.h"
#include "ConfigurationExportService.h"
#include "ConfigurationImportPreview.h"
#include "EnvironmentProfileController.h"
#include "EnvironmentProfileSelector.h"

#include <gtest/gtest.h>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QGroupBox>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTimer>

struct SettingsDialogEnvironmentProfileTestAccess
{
    static void useImportPaths(SettingsDialog& dialog, const QString& path,
                               const QString& backupDirectory)
    {
        dialog.import_file_picker_override_ = [path] { return path; };
        dialog.import_backup_directory_override_ = backupDirectory;
    }
};

namespace {

EnvironmentProfile profile(EnvironmentProfile::Kind kind)
{
    EnvironmentProfile value;
    value.kind = kind;
    value.layout.columns = 1;
    value.layout.rows = 1;
    value.layout.gridTechnicalNames = {QStringLiteral("local")};
    ScreenLayout::Device local;
    local.uuid = QUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
    local.technicalName = QStringLiteral("local");
    local.geometry = QRect(0, 0, 100, 100);
    local.monitors = {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
                       Qt::PrimaryOrientation, false}};
    value.layout.extension = ScreenLayout({local});
    value.devices = {{local.uuid, local.technicalName, DevicePermissions::None}};
    return value;
}

EnvironmentProfileController::Services services()
{
    return {
        [] { return EnvironmentProfileStore::LoadStatus::Loaded; },
        [](EnvironmentProfile::Kind kind) { return std::optional<EnvironmentProfile>(profile(kind)); },
        [] { return std::optional<EnvironmentProfile::Kind>(EnvironmentProfile::Kind::Home); },
        [] { return std::optional<QString>(QStringLiteral("g1")); },
        [](const EnvironmentProfile&) { return EnvironmentProfileStore::SaveResult::Success; },
        [](const EnvironmentProfile&, const QString&, const std::optional<QString>&) {
            return EnvironmentProfileStore::Mutation{};
        },
        [](EnvironmentProfile::Kind, const QString&, const std::optional<QString>&) {
            return EnvironmentProfileStore::Mutation{};
        },
        [](const QString&) { return EnvironmentProfileStore::SaveResult::Success; },
        [](const QString& expected,
           const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            if (expected != QStringLiteral("g1"))
                return EnvironmentProfileStore::SaveResult::ConcurrentModification;
            return consumer({EnvironmentProfile::Kind::Home, QStringLiteral("g1"),
                             profile(EnvironmentProfile::Kind::Home)})
                ? EnvironmentProfileStore::SaveResult::Success
                : EnvironmentProfileStore::SaveResult::InvalidProfile;
        },
        [] { return profile(EnvironmentProfile::Kind::Home).layout; },
        [](const EnvironmentProfile::Layout&) { return true; },
        [](const QUuid&) { return DevicePermissions::Mask(DevicePermissions::None); },
        [](const QUuid&, DevicePermissions::Permission) { return false; },
        [] { return false; },
        [] { return false; },
        [] {
            QList<EnvironmentProfile> profiles;
            for (const auto kind : EnvironmentProfile::canonicalKinds())
                profiles.push_back(profile(kind));
            return profiles;
        },
        [](const QList<EnvironmentProfile>&, EnvironmentProfile::Kind,
           const QString&, const std::optional<QString>&) {
            return EnvironmentProfileStore::Mutation{};
        },
    };
}

QHash<QString, QVariant> environmentSnapshot(QSettings& settings)
{
    QHash<QString, QVariant> result;
    for (const QString& key : settings.allKeys()) {
        if (key.startsWith(QStringLiteral("environmentProfiles/")))
            result.insert(key, settings.value(key));
    }
    return result;
}

} // namespace

TEST(SettingsDialogEnvironmentProfileTests, RealDialogContainsSectionAndBlockedAcceptDoesNotMutateProfiles)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"), 1);
    settings.setValue(QStringLiteral("environmentProfiles/sentinel"), QStringLiteral("unchanged"));

    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) { secrets.insert(key, value); return true; },
        [&secrets](const QString& key) { secrets.remove(key); return true; }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    const auto before = environmentSnapshot(settings);

    std::unique_ptr<SettingsDialog> dialog;
    ASSERT_NO_THROW(dialog = std::make_unique<SettingsDialog>(nullptr, config, &controller, true, true, true));
    auto* selector = dialog->findChild<EnvironmentProfileSelector*>(QStringLiteral("environmentProfileSelector"));
    ASSERT_NE(selector, nullptr);
    auto* group = qobject_cast<QGroupBox*>(selector->parentWidget());
    ASSERT_NE(group, nullptr);
    EXPECT_EQ(group->title(), QStringLiteral("Perfis de ambiente"));
    auto* apply = selector->findChild<QPushButton*>(QStringLiteral("applyEnvironmentProfileButton"));
    auto* capture = selector->findChild<QPushButton*>(QStringLiteral("captureEnvironmentProfileButton"));
    ASSERT_NE(apply, nullptr);
    ASSERT_NE(capture, nullptr);
    EXPECT_FALSE(apply->isEnabled());
    EXPECT_FALSE(capture->isEnabled());
    auto* exportButton = dialog->findChild<QPushButton*>(QStringLiteral("exportConfigurationButton"));
    auto* importButton = dialog->findChild<QPushButton*>(QStringLiteral("importConfigurationButton"));
    ASSERT_NE(exportButton, nullptr);
    ASSERT_NE(importButton, nullptr);
    EXPECT_TRUE(exportButton->isEnabled());
    EXPECT_FALSE(importButton->isEnabled());

    apply->click();
    capture->click();
    ASSERT_NO_THROW(ASSERT_TRUE(QMetaObject::invokeMethod(dialog.get(), "accept", Qt::DirectConnection)));

    EXPECT_EQ(dialog->result(), QDialog::Accepted);
    EXPECT_EQ(environmentSnapshot(settings), before);
}

TEST(SettingsDialogEnvironmentProfileTests, FailedSaveRestoresInMemoryCandidateAndFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("failed-save.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("original-host"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.sync();
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt
                                         : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            if (key == QStringLiteral("InputLeap/file-transfer-pairing-code"))
                return false;
            secrets.insert(key, value);
            return true;
        },
        [&secrets](const QString& key) {
            secrets.remove(key);
            return true;
        }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    SettingsDialog dialog(nullptr, config, &controller, true, false, false);
    QSignalSpy saveFailed(&dialog, &SettingsDialog::configurationSaveFailed);
    auto* screenName = dialog.findChild<QLineEdit*>(QStringLiteral("m_pLineEditScreenName"));
    auto* port = dialog.findChild<QSpinBox*>(QStringLiteral("m_pSpinBoxPort"));
    auto* crypto = dialog.findChild<QCheckBox*>(QStringLiteral("m_pCheckBoxEnableCrypto"));
    auto* pairing = dialog.findChild<QLineEdit*>(QStringLiteral("pairingCodeEdit"));
    ASSERT_NE(screenName, nullptr);
    ASSERT_NE(port, nullptr);
    ASSERT_NE(crypto, nullptr);
    ASSERT_NE(pairing, nullptr);
    screenName->setText(QStringLiteral("candidate-host"));
    port->setValue(24809);
    crypto->setChecked(false);
    pairing->setText(QStringLiteral("[REDACTED]"));

    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                if (message->windowTitle() == QStringLiteral("Configurações")) {
                    message->done(QMessageBox::Ok);
                    return;
                }
            }
        }
    });
    ASSERT_TRUE(QMetaObject::invokeMethod(&dialog, "accept", Qt::DirectConnection));

    EXPECT_NE(dialog.result(), QDialog::Accepted);
    EXPECT_EQ(config.screenName(), QStringLiteral("original-host"));
    EXPECT_EQ(config.port(), 24800);
    EXPECT_TRUE(config.getCryptoEnabled());
    EXPECT_TRUE(config.fileTransferPairingCode().isEmpty());
    EXPECT_TRUE(config.settingsLoadFailed());
    EXPECT_EQ(saveFailed.count(), 1);
}

TEST(SettingsDialogEnvironmentProfileTests, ConcurrentSaveExplainsExternalChangeAndFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("concurrent-save.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("original-host"));
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt
                                         : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value);
            return true;
        },
        [&secrets](const QString& key) {
            secrets.remove(key);
            return true;
        }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    SettingsDialog dialog(nullptr, config, &controller, true, false, false);
    QSignalSpy saveFailed(&dialog, &SettingsDialog::configurationSaveFailed);

    QSettings external(path, QSettings::IniFormat);
    external.setValue(QStringLiteral("language"), QStringLiteral("en"));
    external.sync();

    QString warningText;
    QTimer::singleShot(0, [&warningText] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                if (message->windowTitle() == QStringLiteral("Configurações")) {
                    warningText = message->text();
                    message->button(QMessageBox::Ok)->click();
                    return;
                }
            }
        }
    });
    ASSERT_TRUE(QMetaObject::invokeMethod(&dialog, "accept", Qt::DirectConnection));

    EXPECT_NE(dialog.result(), QDialog::Accepted);
    EXPECT_TRUE(warningText.contains(QStringLiteral("alteradas por outra instância")));
    EXPECT_EQ(saveFailed.count(), 1);
    EXPECT_FALSE(config.settingsLoadFailed());
}

TEST(SettingsDialogEnvironmentProfileTests, AutoStartControlDescribesStartingInputLeap)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value);
            return true;
        },
        [&secrets](const QString& key) {
            secrets.remove(key);
            return true;
        }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());

    SettingsDialog dialog(nullptr, config, &controller, true, false, false);
    auto* autoStart = dialog.findChild<QCheckBox*>(QStringLiteral("m_pCheckBoxAutoStart"));
    ASSERT_NE(autoStart, nullptr);
    EXPECT_EQ(autoStart->text(), QStringLiteral("Iniciar o InputLeap automaticamente"));
}

TEST(SettingsDialogEnvironmentProfileTests, KeepsActionButtonsVisibleOutsideScrollableContent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value);
            return true;
        },
        [&secrets](const QString& key) {
            secrets.remove(key);
            return true;
        }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());

    SettingsDialog dialog(nullptr, config, &controller, true, false, false);
    auto* scrollArea = dialog.findChild<QScrollArea*>(QStringLiteral("settingsScrollArea"));
    auto* buttons = dialog.findChild<QDialogButtonBox*>(QStringLiteral("buttonBox"));
    ASSERT_NE(scrollArea, nullptr);
    ASSERT_NE(buttons, nullptr);
    auto* saveButton = buttons->button(QDialogButtonBox::Ok);
    auto* cancelButton = buttons->button(QDialogButtonBox::Cancel);
    ASSERT_NE(saveButton, nullptr);
    ASSERT_NE(cancelButton, nullptr);
    EXPECT_FALSE(scrollArea->isAncestorOf(buttons));

    dialog.resize(dialog.width(), 480);
    dialog.show();
    QApplication::processEvents();
    const QRect buttonsInDialog(buttons->mapTo(&dialog, QPoint(0, 0)), buttons->size());
    EXPECT_LE(buttonsInDialog.bottom(), dialog.contentsRect().bottom());
    EXPECT_GE(buttonsInDialog.top(), scrollArea->geometry().bottom());
    EXPECT_EQ(saveButton->text(), QStringLiteral("Salvar"));
    EXPECT_EQ(cancelButton->text(), QStringLiteral("Cancelar"));
    EXPECT_TRUE(saveButton->isVisible());
    EXPECT_TRUE(cancelButton->isVisible());
    const QRect saveInDialog(saveButton->mapTo(&dialog, QPoint(0, 0)), saveButton->size());
    const QRect cancelInDialog(cancelButton->mapTo(&dialog, QPoint(0, 0)), cancelButton->size());
    EXPECT_TRUE(dialog.contentsRect().contains(saveInDialog));
    EXPECT_TRUE(dialog.contentsRect().contains(cancelInDialog));
    EXPECT_FALSE(saveInDialog.intersects(cancelInDialog));
}

TEST(SettingsDialogEnvironmentProfileTests, CancellingPublicExportDoesNotReadCredentialStore)
{
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
    const auto restoreNativeDialogs = qScopeGuard([] {
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, false);
    });
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    secrets.insert(QStringLiteral("InputLeap/file-transfer-pairing-code"),
                   QByteArrayLiteral("PAIRING-CODE"));
    int credentialReads = 0;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets, &credentialReads](const QString& key) -> std::optional<QByteArray> {
            ++credentialReads;
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value);
            return true;
        },
        [&secrets](const QString& key) {
            secrets.remove(key);
            return true;
        }));
    credentialReads = 0;
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    SettingsDialog dialog(nullptr, config, &controller, true, true, true);
    auto* exportButton = dialog.findChild<QPushButton*>(
        QStringLiteral("exportConfigurationButton"));
    ASSERT_NE(exportButton, nullptr);

    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            auto* modal = qobject_cast<QDialog*>(widget);
            if (modal && modal->windowTitle() == QStringLiteral("Exportar backup")) {
                modal->reject();
                return;
            }
        }
    });
    exportButton->click();

    EXPECT_EQ(credentialReads, 0);
}

TEST(SettingsDialogEnvironmentProfileTests, RuntimeInvalidationDuringSensitiveExportPreventsReadAndWrite)
{
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
    const auto restoreNativeDialogs = qScopeGuard([] {
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, false);
    });
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    secrets.insert(QStringLiteral("InputLeap/file-transfer-pairing-code"),
                   QByteArrayLiteral("PAIRING-CODE"));
    int credentialReads = 0;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets, &credentialReads](const QString& key) -> std::optional<QByteArray> {
            ++credentialReads;
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value); return true;
        },
        [&secrets](const QString& key) { secrets.remove(key); return true; }));
    credentialReads = 0;
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    SettingsDialog dialog(nullptr, config, &controller, true, true, true);
    auto* exportButton = dialog.findChild<QPushButton*>(
        QStringLiteral("exportConfigurationButton"));
    ASSERT_NE(exportButton, nullptr);
    const QString destination = directory.filePath(QStringLiteral("blocked.ilconfig"));

    QTimer automation;
    QObject::connect(&automation, &QTimer::timeout, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* picker = qobject_cast<QFileDialog*>(widget)) {
                if (picker->windowTitle() == QStringLiteral("Exportar backup")) {
                    picker->selectFile(destination);
                    QMetaObject::invokeMethod(picker, "accept", Qt::DirectConnection);
                    return;
                }
            }
            auto* modal = qobject_cast<QDialog*>(widget);
            if (!modal || modal->windowTitle() != QStringLiteral("Proteção do backup"))
                continue;
            auto* includeSensitive = modal->findChild<QCheckBox*>();
            ASSERT_NE(includeSensitive, nullptr);
            includeSensitive->setChecked(true);
            const auto edits = modal->findChildren<QLineEdit*>();
            ASSERT_EQ(edits.size(), 2);
            edits.at(0)->setText(QStringLiteral("backup-password"));
            edits.at(1)->setText(QStringLiteral("backup-password"));
            dialog.invalidateRuntimeOperations();
            automation.stop();
            return;
        }
    });
    automation.start(5);
    exportButton->click();

    EXPECT_EQ(credentialReads, 0);
    EXPECT_FALSE(QFile::exists(destination));
    EXPECT_EQ(dialog.result(), QDialog::Rejected);
}

TEST(SettingsDialogEnvironmentProfileTests, RuntimeInvalidationDuringImportReviewPreventsApply)
{
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
    const auto restoreNativeDialogs = qScopeGuard([] {
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, false);
    });
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value); return true;
        },
        [&secrets](const QString& key) { secrets.remove(key); return true; }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(config, controller);
    const auto currentSnapshot = appTarget.snapshot();
    ASSERT_TRUE(currentSnapshot);
    const QString originalLanguage = currentSnapshot->preferences.language();
    const QString candidateLanguage = originalLanguage == QStringLiteral("en")
        ? QStringLiteral("pt-BR") : QStringLiteral("en");
    const auto& current = currentSnapshot->preferences;
    ConfigurationPublicSnapshot candidate;
    candidate.preferences = *ConfigurationPortablePreferences::create(
        current.port(), current.logLevel(), candidateLanguage,
        current.cryptoEnabled(), current.requireClientCertificate(),
        current.autoHide(), current.autoStart(), current.minimizeToTray());
    const QUuid candidateUuid(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        ScreenLayout::Device layoutDevice{
            candidateUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100),
            {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
              Qt::PrimaryOrientation, false}}};
        EnvironmentProfile candidateProfile;
        candidateProfile.kind = kind;
        candidateProfile.layout = {
            1, 1, {QStringLiteral("desktop")}, ScreenLayout({layoutDevice})};
        candidateProfile.devices = {{candidateUuid, QStringLiteral("desktop"),
                                     DevicePermissions::ControlMouseKeyboard}};
        candidate.environmentProfiles.profiles.push_back(candidateProfile);
    }
    candidate.environmentProfiles.activeKind = EnvironmentProfile::Kind::Home;
    const auto package = ConfigurationExportService::build(candidate, {}, {});
    ASSERT_TRUE(package.package);
    const QString source = directory.filePath(QStringLiteral("candidate.ilconfig"));
    ASSERT_EQ(ConfigurationExportService::writeAtomically(source, *package.package),
              ConfigurationExportService::Error::None);

    SettingsDialog dialog(nullptr, config, &controller, true, true, true);
    auto* importButton = dialog.findChild<QPushButton*>(
        QStringLiteral("importConfigurationButton"));
    ASSERT_NE(importButton, nullptr);
    QTimer automation;
    QObject::connect(&automation, &QTimer::timeout, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* picker = qobject_cast<QFileDialog*>(widget)) {
                if (picker->windowTitle() == QStringLiteral("Importar backup")) {
                    picker->selectFile(source);
                    QMetaObject::invokeMethod(picker, "accept", Qt::DirectConnection);
                    return;
                }
            }
            auto* modal = qobject_cast<QMessageBox*>(widget);
            if (!modal || modal->windowTitle() != QStringLiteral("Revisar importação"))
                continue;
            dialog.invalidateRuntimeOperations();
            automation.stop();
            return;
        }
    });
    automation.start(5);
    importButton->click();

    const auto after = appTarget.snapshot();
    ASSERT_TRUE(after);
    EXPECT_EQ(after->preferences.language(), originalLanguage);
    EXPECT_EQ(dialog.result(), QDialog::Rejected);
}

TEST(SettingsDialogEnvironmentProfileTests,
     ImportFailureAfterAuthorizationRevocationCannotOpenAnotherModal)
{
    QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
    const auto restoreDialogMode = qScopeGuard([] {
        QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs, false);
    });
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("revoked-import.ini")),
                       QSettings::IniFormat);
    QHash<QString, QByteArray> secrets;
    AppConfig config(&settings, SecureCredentialStore(
        [&secrets](const QString& key) -> std::optional<QByteArray> {
            const auto it = secrets.constFind(key);
            return it == secrets.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&secrets](const QString& key, const QByteArray& value) {
            secrets.insert(key, value); return true;
        },
        [&secrets](const QString& key) { secrets.remove(key); return true; }));
    EnvironmentProfileController controller(services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(config, controller);
    const auto currentSnapshot = appTarget.snapshot();
    ASSERT_TRUE(currentSnapshot);

    for (const auto& currentProfile : currentSnapshot->environmentProfiles.profiles) {
        ASSERT_TRUE(currentProfile.isValid())
            << "invalid current profile kind=" << static_cast<int>(currentProfile.kind);
    }
    const auto environmentValidation = EnvironmentProfileJsonCodec::decode(
        EnvironmentProfileJsonCodec::encode(currentSnapshot->environmentProfiles));
    ASSERT_EQ(environmentValidation.error, EnvironmentProfileJsonCodec::Error::None)
        << "current environment codec error="
        << static_cast<int>(environmentValidation.error)
        << " profile count=" << currentSnapshot->environmentProfiles.profiles.size();

    ConfigurationPublicSnapshot candidate;
    const auto& current = currentSnapshot->preferences;
    const QString candidateLanguage = current.language() == QStringLiteral("en")
        ? QStringLiteral("pt-BR") : QStringLiteral("en");
    candidate.preferences = *ConfigurationPortablePreferences::create(
        current.port(), current.logLevel(), candidateLanguage,
        current.cryptoEnabled(), current.requireClientCertificate(),
        current.autoHide(), current.autoStart(), current.minimizeToTray());
    const QUuid candidateUuid(QStringLiteral("{33333333-3333-3333-3333-333333333333}"));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        ScreenLayout::Device layoutDevice{
            candidateUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100),
            {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
              Qt::PrimaryOrientation, false}}};
        EnvironmentProfile candidateProfile;
        candidateProfile.kind = kind;
        candidateProfile.layout = {
            1, 1, {QStringLiteral("desktop")}, ScreenLayout({layoutDevice})};
        candidateProfile.devices = {{candidateUuid, QStringLiteral("desktop"),
                                     DevicePermissions::ControlMouseKeyboard}};
        candidate.environmentProfiles.profiles.push_back(candidateProfile);
    }
    candidate.environmentProfiles.activeKind = EnvironmentProfile::Kind::Home;
    const auto package = ConfigurationExportService::build(candidate, {}, {});
    ASSERT_TRUE(package.package);
    SensitiveBytes emptyPassword;
    const auto fixturePreview = ConfigurationImportPreview::create(
        *package.package, *currentSnapshot, emptyPassword);
    ASSERT_EQ(fixturePreview.error, ConfigurationImportPreview::Error::None)
        << "fixture preview error=" << static_cast<int>(fixturePreview.error);
    ASSERT_TRUE(fixturePreview.preview);
    const QString source = directory.filePath(QStringLiteral("revoked-candidate.ilconfig"));
    ASSERT_EQ(ConfigurationExportService::writeAtomically(source, *package.package),
              ConfigurationExportService::Error::None);

    SettingsDialog dialog(nullptr, config, &controller, true, false, false);
    SettingsDialogEnvironmentProfileTestAccess::useImportPaths(
        dialog, source, directory.filePath(QStringLiteral("backups")));
    auto* importButton = dialog.findChild<QPushButton*>(
        QStringLiteral("importConfigurationButton"));
    ASSERT_NE(importButton, nullptr);
    bool invalidated = false;
    int postRevocationModals = 0;
    QStringList observedWindows;
    QObject::connect(&controller, &EnvironmentProfileController::authorizationInvalidated,
                     &dialog, [&] {
        invalidated = true;
        dialog.invalidateRuntimeOperations();
    });

    QTimer automation;
    QObject::connect(&automation, &QTimer::timeout, [&] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->isVisible()) {
                const QString observation = QStringLiteral("%1:%2")
                    .arg(QString::fromLatin1(widget->metaObject()->className()),
                         widget->windowTitle());
                if (!observedWindows.contains(observation))
                    observedWindows.append(observation);
            }
            if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                if (invalidated) {
                    ++postRevocationModals;
                    message->done(QMessageBox::Ok);
                    automation.stop();
                    return;
                }
                if (message->windowTitle() == QStringLiteral("Importar backup")) {
                    observedWindows.append(QStringLiteral("message:%1").arg(message->text()));
                    message->done(QMessageBox::Ok);
                    automation.stop();
                    return;
                }
                if (message->windowTitle() == QStringLiteral("Revisar importação") ||
                    message->windowTitle() == QStringLiteral("Arquivo sem autenticação")) {
                    auto* yes = message->button(QMessageBox::Yes);
                    ASSERT_NE(yes, nullptr);
                    yes->click();
                    return;
                }
            }
            auto* modal = qobject_cast<QDialog*>(widget);
            if (!modal || modal->windowTitle() != QStringLiteral("Senhas da importação"))
                continue;
            const auto edits = modal->findChildren<QLineEdit*>();
            ASSERT_EQ(edits.size(), 3);
            edits.at(1)->setText(QStringLiteral("automatic-backup-password"));
            edits.at(2)->setText(QStringLiteral("automatic-backup-password"));
            QMetaObject::invokeMethod(modal, "accept", Qt::DirectConnection);
            return;
        }
    });
    bool automationTimedOut = false;
    QTimer::singleShot(5000, &dialog, [&] {
        automationTimedOut = true;
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* modal = qobject_cast<QDialog*>(widget))
                modal->reject();
        }
    });
    automation.start(5);
    importButton->click();
    automation.stop();

    EXPECT_FALSE(automationTimedOut) << observedWindows.join(QStringLiteral(" | ")).toStdString();
    EXPECT_TRUE(invalidated) << observedWindows.join(QStringLiteral(" | ")).toStdString();
    EXPECT_EQ(postRevocationModals, 0);
    EXPECT_EQ(dialog.result(), QDialog::Rejected);
}
