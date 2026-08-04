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

#pragma once

#include <QDialog>
#include <QLineEdit>
#include <functional>
#include <memory>

class AppConfig;
class EnvironmentProfileController;
class EnvironmentProfileSelector;
class EnvironmentProfileUiBinding;
class QPushButton;
struct SettingsDialogEnvironmentProfileTestAccess;

namespace Ui
{
    class SettingsDialog;
}

class SettingsDialog : public QDialog
{
    Q_OBJECT

    public:
        SettingsDialog(QWidget* parent, AppConfig& config);
        SettingsDialog(QWidget* parent, AppConfig& config,
                       EnvironmentProfileController* profileController,
                       bool profilesAvailable, bool profilesBusy,
                       bool externalConfig = false);
        ~SettingsDialog() override;
        void setEnvironmentProfileAvailability(bool available, bool busy,
                                               bool externalConfig = false);
        void invalidateRuntimeOperations();

    Q_SIGNALS:
        void requestLanguageChange(QString newLang);
        void configurationImported();
        void requestCoreRestart();
        void configurationSaveFailed();

    protected:
        void accept() override;
        void reject() override;
        void changeEvent(QEvent* event) override;

    private:
        friend struct SettingsDialogEnvironmentProfileTestAccess;
        void languageChanged(int index);
        void logToFileChanged(bool checked);
        void browseLogClicked();
        void browseReceiveDirectoryClicked();
        void openReceiveDirectoryClicked();
        void exportConfiguration();
        void importConfiguration();
        void refreshPortableFields();
        quint64 beginRuntimeOperation() const noexcept;
        bool runtimeOperationAuthorized(quint64 generation) const noexcept;

        std::unique_ptr<Ui::SettingsDialog> ui_;
        AppConfig& app_config_;
        QLineEdit* receive_directory_edit_ = nullptr;
        QLineEdit* pairing_code_edit_ = nullptr;
        QPushButton* import_configuration_button_ = nullptr;
        EnvironmentProfileController* profile_controller_ = nullptr;
        EnvironmentProfileSelector* environment_profile_selector_ = nullptr;
        std::unique_ptr<EnvironmentProfileUiBinding> environment_profile_binding_;
        std::function<QString()> import_file_picker_override_;
        QString import_backup_directory_override_;
        quint64 runtime_operation_generation_ = 1;
        bool runtime_operations_authorized_ = true;
};
