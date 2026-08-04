#include "DevicePermissionsDialog.h"
#include "DeviceRegistry.h"
#include <QComboBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {
QString presetExplanation(DevicePermissionsDialog::Preset preset) {
    switch (preset) {
    case DevicePermissionsDialog::Preset::FullAccess: return QObject::tr("Permite controlar mouse e teclado, enviar e receber arquivos, compartilhar a área de transferência e conectar automaticamente. Não abre arquivos automaticamente.");
    case DevicePermissionsDialog::Preset::ControlOnly: return QObject::tr("Permite somente controlar mouse e teclado. Arquivos, área de transferência e conexão automática continuam bloqueados.");
    case DevicePermissionsDialog::Preset::FilesOnly: return QObject::tr("Permite enviar e receber arquivos. Não permite controle, área de transferência ou conexão automática.");
    case DevicePermissionsDialog::Preset::Custom: return QObject::tr("Escolha as permissões individualmente. A abertura automática de arquivos permanece bloqueada nesta tela e só pode ser liberada por uma ação explícita separada.");
    }
    return {};
}
}

DevicePermissions::Mask DevicePermissionsDialog::maskForPreset(Preset preset) {
    switch (preset) {
    case Preset::FullAccess: return DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles | DevicePermissions::ShareClipboard | DevicePermissions::AutoConnect;
    case Preset::ControlOnly: return DevicePermissions::ControlMouseKeyboard;
    case Preset::FilesOnly: return DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles;
    case Preset::Custom: return DevicePermissions::None;
    }
    return DevicePermissions::None;
}

DevicePermissionsDialog::DevicePermissionsDialog(DeviceRegistry& registry, const QUuid& uuid, QWidget* parent)
    : QDialog(parent), registry_(registry), uuid_(uuid) {
    setWindowTitle(tr("Permissões deste computador"));
    setModal(true);
    auto* layout = new QVBoxLayout(this);
    auto* title = new QLabel(tr("Escolha o que este computador pode fazer"), this);
    title->setAccessibleName(title->text());
    layout->addWidget(title);
    preset_ = new QComboBox(this);
    preset_->addItem(tr("Acesso completo"), int(Preset::FullAccess));
    preset_->addItem(tr("Somente controle"), int(Preset::ControlOnly));
    preset_->addItem(tr("Somente arquivos"), int(Preset::FilesOnly));
    preset_->addItem(tr("Personalizado"), int(Preset::Custom));
    preset_->setAccessibleName(tr("Preset de permissões"));
    layout->addWidget(preset_);
    auto addPermission = [this, layout](const QString& text, const QString& name, DevicePermissions::Permission permission) {
        auto* check = new QCheckBox(text, this);
        check->setAccessibleName(name);
        check->setProperty("permission", static_cast<uint>(permission));
        layout->addWidget(check);
        return check;
    };
    controlMouseKeyboard_ = addPermission(tr("Controlar mouse e teclado"), tr("Permissão: controlar mouse e teclado"), DevicePermissions::ControlMouseKeyboard);
    sendFiles_ = addPermission(tr("Enviar arquivos"), tr("Permissão: enviar arquivos"), DevicePermissions::SendFiles);
    receiveFiles_ = addPermission(tr("Receber arquivos"), tr("Permissão: receber arquivos"), DevicePermissions::ReceiveFiles);
    shareClipboard_ = addPermission(tr("Compartilhar área de transferência"), tr("Permissão: compartilhar área de transferência"), DevicePermissions::ShareClipboard);
    autoConnect_ = addPermission(tr("Conectar automaticamente"), tr("Permissão: conectar automaticamente"), DevicePermissions::AutoConnect);
    auto* safeOpen = new QLabel(tr("Abrir arquivos automaticamente: bloqueado (não disponível em Personalizado)"), this);
    safeOpen->setAccessibleName(tr("Abertura automática de arquivos bloqueada"));
    safeOpen->setWordWrap(true);
    layout->addWidget(safeOpen);
    explanation_ = new QLabel(this); explanation_->setWordWrap(true); layout->addWidget(explanation_);
    status_ = new QLabel(this); status_->setWordWrap(true); layout->addWidget(status_);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    auto* revoke = buttons->addButton(tr("Revogar tudo"), QDialogButtonBox::DestructiveRole);
    layout->addWidget(buttons);
    connect(preset_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { updatePresetView(); });
    connect(buttons, &QDialogButtonBox::accepted, this, [this] { if (applyPreset(Preset(preset_->currentData().toInt()))) accept(); });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(revoke, &QPushButton::clicked, this, [this] { if (revokeAll()) accept(); });
    updatePresetView();
    refreshState();
}

bool DevicePermissionsDialog::applyMask(DevicePermissions::Mask mask) {
    if (uuid_.isNull() || !registry_.find(uuid_).has_value()) { status_->setText(tr("Computador desconhecido: nada foi alterado.")); return false; }
    if (!registry_.setPermissions(uuid_, mask)) { status_->setText(tr("Não foi possível salvar; as permissões anteriores foram mantidas.")); refreshState(); return false; }
    refreshState(); return true;
}
bool DevicePermissionsDialog::applyPreset(Preset preset) { return applyMask(preset == Preset::Custom ? selectedMask() : maskForPreset(preset)); }
bool DevicePermissionsDialog::revokeAll() { return applyMask(DevicePermissions::None); }
QString DevicePermissionsDialog::statusText() const { return status_ ? status_->text() : QString(); }
void DevicePermissionsDialog::refreshState() {
    const auto mask = registry_.permissions(uuid_);
    if (status_) status_->setText(mask ? tr("Permissões ativas: %1").arg(DevicePermissions().labels(mask).join(tr(", "))) : tr("Nenhuma permissão ativa"));
    if (explanation_) explanation_->setText(presetExplanation(Preset(preset_ ? preset_->currentData().toInt() : int(Preset::Custom))));
}

DevicePermissions::Mask DevicePermissionsDialog::selectedMask() const {
    DevicePermissions::Mask mask = DevicePermissions::None;
    const QCheckBox* checks[] = {controlMouseKeyboard_, sendFiles_, receiveFiles_, shareClipboard_, autoConnect_};
    for (const auto* check : checks) if (check->isChecked()) mask |= check->property("permission").toUInt();
    return mask;
}

void DevicePermissionsDialog::setControlsMask(DevicePermissions::Mask mask) {
    QCheckBox* checks[] = {controlMouseKeyboard_, sendFiles_, receiveFiles_, shareClipboard_, autoConnect_};
    for (auto* check : checks) check->setChecked(mask & check->property("permission").toUInt());
}

void DevicePermissionsDialog::updatePresetView() {
    const auto preset = Preset(preset_->currentData().toInt());
    explanation_->setText(presetExplanation(preset));
    setControlsMask(preset == Preset::Custom ? registry_.permissions(uuid_) : maskForPreset(preset));
    const bool editable = preset == Preset::Custom;
    for (auto* check : {controlMouseKeyboard_, sendFiles_, receiveFiles_, shareClipboard_, autoConnect_}) check->setEnabled(editable);
}
