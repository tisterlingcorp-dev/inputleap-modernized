/*
 * InputLeap -- mouse and keyboard sharing utility
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

#include "ServerConfigDialog.h"
#include <ui_ServerConfigDialog.h>

#include "ServerConfig.h"
#include "HotkeyDialog.h"
#include "ActionDialog.h"
#include "ScreenLayoutEditorWidget.h"

#include <QtCore>
#include <QtGui>
#include <QPushButton>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QFrame>
#include <QCheckBox>

#include <algorithm>

ServerConfigDialog::ServerConfigDialog(QWidget* parent, ServerConfig& config, const QString& defaultScreenName, const QList<DeviceInfo>& devices) :
    QDialog(parent, Qt::WindowTitleHint | Qt::WindowSystemMenuHint),
    ui_{std::make_unique<Ui::ServerConfigDialog>()},
    m_OrigServerConfig(config),
    m_ServerConfig(config),
    m_ScreenSetupModel(serverConfig().screens(), serverConfig().numColumns(), serverConfig().numRows()),
    m_Devices(devices),
    m_Message("")
{
    ui_->setupUi(this);
    setMinimumSize(840, 620);

    auto* rootLayout = qobject_cast<QVBoxLayout*>(layout());
    if (rootLayout != nullptr) {
        auto* header = new QFrame(this);
        header->setObjectName("serverConfigHeader");
        auto* headerLayout = new QVBoxLayout(header);
        headerLayout->setContentsMargins(20, 15, 20, 15);
        headerLayout->setSpacing(3);
        auto* title = new QLabel(tr("Configuração do servidor"), header);
        title->setObjectName("serverConfigTitle");
        auto* subtitle = new QLabel(
            tr("Organize as telas, crie atalhos e ajuste como os computadores se comunicam."),
            header
        );
        subtitle->setObjectName("serverConfigSubtitle");
        subtitle->setWordWrap(true);
        headerLayout->addWidget(title);
        headerLayout->addWidget(subtitle);
        rootLayout->insertWidget(0, header);
    }

    setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QFrame#serverConfigHeader { background: #0f172a; border-radius: 12px; }"
        "QLabel#serverConfigTitle { color: #f8fafc; font-size: 17px; font-weight: 700; }"
        "QLabel#serverConfigSubtitle { color: #94a3b8; font-size: 9pt; }"
        "QTabWidget::pane { border: 1px solid #d8dee8; background: #ffffff; border-radius: 10px; top: -1px; }"
        "QTabBar { background: #e8edf5; border-radius: 9px; }"
        "QTabBar::tab { background: transparent; color: #475569; border: none; "
            "padding: 10px 18px; margin: 4px 2px; border-radius: 7px; font-weight: 600; }"
        "QTabBar::tab:hover { background: #f8fafc; color: #1d4ed8; }"
        "QTabBar::tab:selected { background: #ffffff; color: #1d4ed8; border: 1px solid #c7d2fe; font-weight: 700; }"
        "QGroupBox { background: #ffffff; border: 1px solid #d8dee8; border-radius: 8px; "
            "margin-top: 14px; padding: 20px 14px 14px 14px; font-weight: 600; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #233142; }"
        "QLabel, QCheckBox { color: #334155; font-size: 9pt; }"
        "QLabel[muted=\"true\"] { color: #64748b; padding: 8px 2px; }"
        "QCheckBox { spacing: 8px; padding: 2px; }"
        "QSpinBox, QListWidget { background: #ffffff; border: 1px solid #aab4c3; "
            "border-radius: 6px; padding: 5px 8px; selection-background-color: #dbeafe; }"
        "QSpinBox:focus, QListWidget:focus { border-color: #2563eb; }"
        "QPushButton { background: #ffffff; color: #334155; border: 1px solid #aab4c3; border-radius: 6px; "
            "padding: 7px 16px; min-width: 72px; font-weight: 600; }"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2e3; }"
        "QPushButton:pressed { background: #dbeafe; }"
        "QPushButton:default { background: #2563eb; color: #ffffff; border-color: #1d4ed8; }"
        "QPushButton:default:hover { background: #1d4ed8; }"
    );

    ui_->m_pTabWidget->setTabText(ui_->m_pTabWidget->indexOf(ui_->m_pTabScreens),
                                  tr("Telas e conexões"));
    ui_->m_pTabWidget->setTabText(ui_->m_pTabWidget->indexOf(ui_->m_pTabHotkeys),
                                  tr("Teclas de atalho"));
    ui_->m_pTabWidget->setTabText(ui_->m_pTabWidget->indexOf(ui_->m_pTabAdvanced),
                                  tr("Opções avançadas"));
    ui_->m_pGroupSwitch->setTitle(tr("&Troca de tela"));
    ui_->m_pGroupOptions->setTitle(tr("Recursos compartilhados"));
    ui_->m_pCheckBoxSwitchDelay->setText(tr("Esperar antes de trocar de computador"));
    ui_->m_pCheckBoxSwitchDoubleTap->setText(tr("Exigir dois toques na borda da tela"));
    ui_->m_pCheckBoxScreenSaverSync->setText(tr("Sincronizar o protetor de tela nos computadores"));
    ui_->label_4->setText(tr("Encoste o ponteiro do mouse na borda da tela duas vezes rapidamente."));
    ui_->m_pGroupSwitchCorners->setTitle(tr("&Cantos inativos"));
    ui_->m_pLabelSharingSize->setText(tr("Tamanho máximo da área de transferência"));
    ui_->m_pSpinBoxClipboardSizeLimit->setToolTip(tr("Tamanho máximo, em bytes, para compartilhar pela área de transferência"));
    ui_->m_pCheckBoxEnableDragAndDrop->setText(tr("Permitir transferência de arquivos ao arrastar e soltar"));
    ui_->m_pCheckBoxEnableClipboard->setText(tr("Permitir compartilhamento da área de transferência"));

    const QList<QWidget*> technicalOptions = {
        ui_->m_pCheckBoxHeartbeat,
        ui_->m_pSpinBoxHeartbeat,
        ui_->m_pLabel_16,
        ui_->m_pCheckBoxRelativeMouseMoves,
        ui_->m_pCheckBoxWin32KeepForeground,
        ui_->m_pCheckBoxIgnoreAutoConfigClient,
        ui_->groupBox_3,
        ui_->m_pGroupSwitchCorners
    };
    for (auto* widget : technicalOptions) {
        widget->hide();
    }

    if (auto* advancedLayout = qobject_cast<QGridLayout*>(ui_->m_pTabAdvanced->layout())) {
        auto* explanation = new QLabel(
            tr("As opções mais usadas estão visíveis. Os ajustes técnicos ficam ocultos para evitar alterações acidentais."),
            ui_->m_pTabAdvanced
        );
        explanation->setWordWrap(true);
        explanation->setProperty("muted", true);
        auto* technicalButton = new QPushButton(tr("Mostrar ajustes técnicos"), ui_->m_pTabAdvanced);
        technicalButton->setCheckable(true);
        advancedLayout->addWidget(explanation, 3, 0, 1, 2);
        advancedLayout->addWidget(technicalButton, 4, 0, 1, 2, Qt::AlignLeft);
        connect(technicalButton, &QPushButton::toggled, this,
                [this, technicalOptions, technicalButton, advancedLayout](bool visible) {
            for (auto* widget : technicalOptions) {
                widget->setVisible(visible);
            }
            if (visible) {
                ui_->m_pGroupSwitch->hide();
                advancedLayout->addWidget(ui_->m_pGroupOptions, 0, 0, 1, 2);
                resize(qMax(width(), 980), qMax(height(), 780));
            }
            else {
                advancedLayout->addWidget(ui_->m_pGroupOptions, 0, 1);
                ui_->m_pGroupSwitch->show();
                resize(840, 620);
            }
            advancedLayout->invalidate();
            technicalButton->setText(visible
                ? QObject::tr("Ocultar ajustes técnicos")
                : QObject::tr("Mostrar ajustes técnicos"));
        });
    }
    if (auto* button = ui_->m_pButtonBox->button(QDialogButtonBox::Cancel)) {
        button->setText(tr("Cancelar"));
    }
    if (auto* button = ui_->m_pButtonBox->button(QDialogButtonBox::Ok)) {
        button->setText(tr("Salvar alterações"));
    }

    ui_->m_pCheckBoxHeartbeat->setChecked(serverConfig().hasHeartbeat());
    ui_->m_pSpinBoxHeartbeat->setValue(serverConfig().heartbeat());

    ui_->m_pCheckBoxRelativeMouseMoves->setChecked(serverConfig().relativeMouseMoves());
    ui_->m_pCheckBoxScreenSaverSync->setChecked(serverConfig().screenSaverSync());
    ui_->m_pCheckBoxWin32KeepForeground->setChecked(serverConfig().win32KeepForeground());

    ui_->m_pCheckBoxSwitchDelay->setChecked(serverConfig().hasSwitchDelay());
    ui_->m_pSpinBoxSwitchDelay->setValue(serverConfig().switchDelay());

    ui_->m_pCheckBoxSwitchDoubleTap->setChecked(serverConfig().hasSwitchDoubleTap());
    ui_->m_pSpinBoxSwitchDoubleTap->setValue(serverConfig().switchDoubleTap());

    ui_->m_pCheckBoxCornerTopLeft->setChecked(serverConfig().switchCorner(BaseConfig::SwitchCorner::TopLeft));
    ui_->m_pCheckBoxCornerTopRight->setChecked(serverConfig().switchCorner(BaseConfig::SwitchCorner::TopRight));
    ui_->m_pCheckBoxCornerBottomLeft->setChecked(serverConfig().switchCorner(BaseConfig::SwitchCorner::BottomLeft));
    ui_->m_pCheckBoxCornerBottomRight->setChecked(serverConfig().switchCorner(BaseConfig::SwitchCorner::BottomRight));
    ui_->m_pSpinBoxSwitchCornerSize->setValue(serverConfig().switchCornerSize());

    ui_->m_pCheckBoxIgnoreAutoConfigClient->setChecked(serverConfig().ignoreAutoConfigClient());

    ui_->m_pCheckBoxEnableDragAndDrop->setChecked(serverConfig().enableDragAndDrop());

    ui_->m_pCheckBoxEnableClipboard->setChecked(serverConfig().clipboardSharing());
    const auto clipboardSize = std::min(
        serverConfig().clipboardSharingSize(),
        static_cast<std::size_t>(ui_->m_pSpinBoxClipboardSizeLimit->maximum()));
    ui_->m_pSpinBoxClipboardSizeLimit->setValue(static_cast<int>(clipboardSize));
    ui_->m_pSpinBoxClipboardSizeLimit->setEnabled(serverConfig().clipboardSharing());

    for (const Hotkey& hotkey : serverConfig().hotkeys()) {
        ui_->m_pListHotkeys->addItem(hotkey.text());
    }

    ui_->m_pScreenSetupView->setModel(&m_ScreenSetupModel);

    if (serverConfig().numScreens() == 0)
        model().screen(serverConfig().numColumns() / 2, serverConfig().numRows() / 2) = Screen(defaultScreenName);

    QStringList names; for (const Screen& screen : serverConfig().screens()) names << screen.name();
    m_InitialLegacyNames=names;
    const ScreenLayout layout = serverConfig().screenLayout().synchronizedToLegacyGrid(
        names, serverConfig().numColumns(), serverConfig().numRows());
    QUuid localUuid;
    for (const auto& device : layout.devices()) if (device.technicalName == defaultScreenName) localUuid = device.uuid;
    if (localUuid.isNull() && !layout.devices().empty()) localUuid = layout.devices().front().uuid;
    m_LayoutEditor = new ScreenLayoutEditorWidget(ui_->m_pTabScreens);
    m_LayoutEditor->setObjectName("screenLayoutEditor"); m_LayoutEditor->setLayoutModel(layout, localUuid);
    for(const DeviceInfo& device:m_Devices)m_LayoutEditor->setDevicePresentation(device.uuid(),device.localAlias().isEmpty()?device.technicalName():device.localAlias(),device.operatingSystem());
    auto* technical = new QCheckBox(tr("Mostrar ajustes técnicos"), ui_->m_pTabScreens);
    technical->setObjectName("screenLayoutTechnicalToggle");
    auto* simulation = new QPushButton(tr("Testar passagem do mouse (simulação)"), ui_->m_pTabScreens);
    simulation->setObjectName("screenLayoutSimulationButton");
    simulation->setAccessibleDescription(tr("Simulação visual de cinco segundos; não move o ponteiro."));
    auto* screensLayout = qobject_cast<QVBoxLayout*>(ui_->m_pTabScreens->layout());
    screensLayout->insertWidget(1, m_LayoutEditor, 1); screensLayout->insertWidget(2, simulation, 0, Qt::AlignLeft);
    screensLayout->insertWidget(3, technical, 0, Qt::AlignLeft);
    ui_->m_pScreenSetupView->hide(); ui_->m_pTrashScreenWidget->hide(); ui_->m_pLabelNewScreenWidget->hide();
    connect(technical, &QCheckBox::toggled, this, [this](bool visible) {
        m_LayoutEditor->setTechnicalAdjustmentsVisible(visible); ui_->m_pScreenSetupView->setVisible(visible);
        ui_->m_pTrashScreenWidget->setVisible(visible); ui_->m_pLabelNewScreenWidget->setVisible(visible);
    });
    connect(simulation, &QPushButton::clicked, this, [this, simulation] {
        if (m_LayoutEditor->simulationActive()) { m_LayoutEditor->cancelPassageSimulation(); simulation->setText(tr("Testar passagem do mouse (simulação)")); }
        else { m_LayoutEditor->startPassageSimulation(); simulation->setText(tr("Cancelar simulação")); }
    });
    connect(m_LayoutEditor, &ScreenLayoutEditorWidget::simulationFinished, simulation,
            [this, simulation] { simulation->setText(tr("Testar passagem do mouse (simulação)")); });
}

void ServerConfigDialog::accept()
{
    if (m_LayoutEditor != nullptr) {
        ScreenLayout repaired;
        const bool legacyEdited=m_LayoutEditor->legacyGridVisible();
        if(legacyEdited){
            QStringList currentNames;for(const Screen& screen:serverConfig().screens())currentNames<<screen.name();
            repaired=m_LayoutEditor->layoutModel().synchronizedToLegacyGrid(currentNames,serverConfig().numColumns(),serverConfig().numRows(),m_InitialLegacyNames);
        }else repaired=m_LayoutEditor->layoutModel().repaired();
        if (!repaired.validate().isValid()) {
            QMessageBox::warning(this, tr("Posições inválidas"), tr("Evite posições sobrepostas e mantenha os computadores encostados.")); return;
        }
        if(!legacyEdited){
            const QUuid local = m_LayoutEditor->localUuid();
            const auto exported = ScreenLayoutEditorViewModel(repaired, local).toLegacyGrid(serverConfig().numColumns(), serverConfig().numRows());
            if(!exported){QMessageBox::warning(this,tr("Organização grande demais"),tr("Esta organização não cabe na grade de compatibilidade. Aproxime os computadores ou use até cinco posições adjacentes."));return;}
            const QStringList grid=*exported;
            const std::vector<Screen> old = serverConfig().screens();
            for (int i=0;i<grid.size();++i) { auto found=std::find_if(old.begin(),old.end(),[&](const Screen& s){return s.name()==grid[i];});
                model().screen(i%serverConfig().numColumns(),i/serverConfig().numColumns())=found==old.end()?Screen():*found; }
        }
        serverConfig().setScreenLayout(repaired);
    }
    serverConfig().haveHeartbeat(ui_->m_pCheckBoxHeartbeat->isChecked());
    serverConfig().setHeartbeat(ui_->m_pSpinBoxHeartbeat->value());

    serverConfig().setRelativeMouseMoves(ui_->m_pCheckBoxRelativeMouseMoves->isChecked());
    serverConfig().setScreenSaverSync(ui_->m_pCheckBoxScreenSaverSync->isChecked());
    serverConfig().setWin32KeepForeground(ui_->m_pCheckBoxWin32KeepForeground->isChecked());

    serverConfig().haveSwitchDelay(ui_->m_pCheckBoxSwitchDelay->isChecked());
    serverConfig().setSwitchDelay(ui_->m_pSpinBoxSwitchDelay->value());

    serverConfig().haveSwitchDoubleTap(ui_->m_pCheckBoxSwitchDoubleTap->isChecked());
    serverConfig().setSwitchDoubleTap(ui_->m_pSpinBoxSwitchDoubleTap->value());

    serverConfig().setSwitchCorner(BaseConfig::SwitchCorner::TopLeft,
                                   ui_->m_pCheckBoxCornerTopLeft->isChecked());
    serverConfig().setSwitchCorner(BaseConfig::SwitchCorner::TopRight,
                                   ui_->m_pCheckBoxCornerTopRight->isChecked());
    serverConfig().setSwitchCorner(BaseConfig::SwitchCorner::BottomLeft,
                                   ui_->m_pCheckBoxCornerBottomLeft->isChecked());
    serverConfig().setSwitchCorner(BaseConfig::SwitchCorner::BottomRight,
                                   ui_->m_pCheckBoxCornerBottomRight->isChecked());
    serverConfig().setSwitchCornerSize(ui_->m_pSpinBoxSwitchCornerSize->value());
    serverConfig().setIgnoreAutoConfigClient(ui_->m_pCheckBoxIgnoreAutoConfigClient->isChecked());
    serverConfig().setEnableDragAndDrop(ui_->m_pCheckBoxEnableDragAndDrop->isChecked());
    serverConfig().setClipboardSharing(ui_->m_pCheckBoxEnableClipboard->isChecked());
    serverConfig().setClipboardSharingSize(ui_->m_pSpinBoxClipboardSizeLimit->value());

    // now that the dialog has been accepted, copy the new server config to the original one,
    // which is a reference to the one in MainWindow.
    setOrigServerConfig(serverConfig());

    QDialog::accept();
}

void ServerConfigDialog::on_m_pButtonNewHotkey_clicked()
{
    Hotkey hotkey;
    HotkeyDialog dlg(this, hotkey);
    if (dlg.exec() == QDialog::Accepted)
    {
        serverConfig().hotkeys().push_back(hotkey);
        ui_->m_pListHotkeys->addItem(hotkey.text());
    }
}

void ServerConfigDialog::on_m_pButtonEditHotkey_clicked()
{
    int idx = ui_->m_pListHotkeys->currentRow();
    Q_ASSERT(idx >= 0 && idx < static_cast<int>(serverConfig().hotkeys().size()));
    Hotkey& hotkey = serverConfig().hotkeys()[idx];
    HotkeyDialog dlg(this, hotkey);
    if (dlg.exec() == QDialog::Accepted)
        ui_->m_pListHotkeys->currentItem()->setText(hotkey.text());
}

void ServerConfigDialog::on_m_pButtonRemoveHotkey_clicked()
{
    int idx = ui_->m_pListHotkeys->currentRow();
    Q_ASSERT(idx >= 0 && idx < static_cast<int>(serverConfig().hotkeys().size()));
    serverConfig().hotkeys().erase(serverConfig().hotkeys().begin() + idx);
    ui_->m_pListActions->clear();
    delete ui_->m_pListHotkeys->item(idx);
}

void ServerConfigDialog::on_m_pListHotkeys_itemSelectionChanged()
{
    bool itemsSelected = !ui_->m_pListHotkeys->selectedItems().isEmpty();
    ui_->m_pButtonEditHotkey->setEnabled(itemsSelected);
    ui_->m_pButtonRemoveHotkey->setEnabled(itemsSelected);
    ui_->m_pButtonNewAction->setEnabled(itemsSelected);

    if (itemsSelected && serverConfig().hotkeys().size() > 0)
    {
        ui_->m_pListActions->clear();

        int idx = ui_->m_pListHotkeys->row(ui_->m_pListHotkeys->selectedItems()[0]);

        // There's a bug somewhere around here: We get idx == 1 right after we deleted the next to last item, so idx can
        // only possibly be 0. GDB shows we got called indirectly from the delete line in
        // on_m_pButtonRemoveHotkey_clicked() above, but the delete is of course necessary and seems correct.
        // The while() is a generalized workaround for all that and shouldn't be required.
        while (idx >= 0 && idx >= static_cast<int>(serverConfig().hotkeys().size()))
            idx--;

        Q_ASSERT(idx >= 0 && idx < static_cast<int>(serverConfig().hotkeys().size()));

        const Hotkey& hotkey = serverConfig().hotkeys()[idx];
        for (const Action& action : hotkey.actions()) {
            ui_->m_pListActions->addItem(action.text());
        }
    }
}

void ServerConfigDialog::on_m_pButtonNewAction_clicked()
{
    int idx = ui_->m_pListHotkeys->currentRow();
    Q_ASSERT(idx >= 0 && idx < static_cast<int>(serverConfig().hotkeys().size()));
    Hotkey& hotkey = serverConfig().hotkeys()[idx];

    Action action;
    ActionDialog dlg(this, serverConfig(), hotkey, action);
    if (dlg.exec() == QDialog::Accepted)
    {
        hotkey.appendAction(action);
        ui_->m_pListActions->addItem(action.text());
    }
}

void ServerConfigDialog::on_m_pButtonEditAction_clicked()
{
    int idxHotkey = ui_->m_pListHotkeys->currentRow();
    Q_ASSERT(idxHotkey >= 0 && idxHotkey < static_cast<int>(serverConfig().hotkeys().size()));
    Hotkey& hotkey = serverConfig().hotkeys()[idxHotkey];

    int idxAction = ui_->m_pListActions->currentRow();
    Q_ASSERT(idxAction >= 0 && idxAction < static_cast<int>(hotkey.actions().size()));
    Action action = hotkey.actions()[idxAction];

    ActionDialog dlg(this, serverConfig(), hotkey, action);
    if (dlg.exec() == QDialog::Accepted) {
        hotkey.setAction(idxAction, action);
        ui_->m_pListActions->currentItem()->setText(action.text());
    }
}

void ServerConfigDialog::on_m_pButtonRemoveAction_clicked()
{
    int idxHotkey = ui_->m_pListHotkeys->currentRow();
    Q_ASSERT(idxHotkey >= 0 && idxHotkey < static_cast<int>(serverConfig().hotkeys().size()));
    Hotkey& hotkey = serverConfig().hotkeys()[idxHotkey];

    int idxAction = ui_->m_pListActions->currentRow();
    Q_ASSERT(idxAction >= 0 && idxAction < static_cast<int>(hotkey.actions().size()));

    hotkey.removeAction(idxAction);
    delete ui_->m_pListActions->currentItem();
}

void ServerConfigDialog::on_m_pListActions_itemSelectionChanged()
{
    ui_->m_pButtonEditAction->setEnabled(!ui_->m_pListActions->selectedItems().isEmpty());
    ui_->m_pButtonRemoveAction->setEnabled(!ui_->m_pListActions->selectedItems().isEmpty());
}

void ServerConfigDialog::on_m_pCheckBoxEnableClipboard_stateChanged(int state)
{
    ui_->m_pSpinBoxClipboardSizeLimit->setEnabled(state == Qt::Checked);
}

ServerConfigDialog::~ServerConfigDialog() = default;
