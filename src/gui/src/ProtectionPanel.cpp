#include "ProtectionPanel.h"
#include "DeviceRegistry.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QToolButton>

ProtectionPanel::State ProtectionPanel::stateFor(const ProtectionFacts& f)
{
    if (f.pairedUuid.isNull() || !f.pairedSessionKey) return State::Unpaired;
    const auto required = DevicePermissions::ControlMouseKeyboard | DevicePermissions::ReceiveFiles;
    if (!f.tlsActive || !f.receiverGate || (f.permissions & static_cast<DevicePermissions::Mask>(required)) != static_cast<DevicePermissions::Mask>(required))
        return State::Attention;
    return State::Complete;
}

QString ProtectionPanel::stateLabel(State s)
{
    switch (s) { case State::Complete: return QObject::tr("Proteção completa"); case State::Attention: return QObject::tr("Atenção"); default: return QObject::tr("Sem pareamento"); }
}
QString ProtectionPanel::badgeLabel(const ProtectionFacts& facts)
{
    return stateLabel(stateFor(facts));
}
QString ProtectionPanel::stateExplanation(State s)
{
    switch (s) {
    case State::Complete: return QObject::tr("Este computador está pareado e as permissões básicas estão protegidas.");
    case State::Attention: return QObject::tr("O pareamento existe, mas falta uma confirmação de proteção. Revise as permissões e a conexão segura.");
    default: return QObject::tr("Nenhum computador pareado. A conexão não será tratada como protegida.");
    }
}

ProtectionPanel::ProtectionPanel(DeviceRegistry& registry, QWidget* parent) : QFrame(parent), registry_(registry)
{
    setObjectName("protectionPanel");
    auto* root = new QVBoxLayout(this);
    auto* heading = new QHBoxLayout();
    stateLabel_ = new QLabel(this); stateLabel_->setObjectName("protectionState"); stateLabel_->setAccessibleName(tr("Estado da proteção"));
    heading->addWidget(stateLabel_); heading->addStretch(); root->addLayout(heading);
    explanation_ = new QLabel(this); explanation_->setWordWrap(true); root->addWidget(explanation_);
    technical_ = new QLabel(tr("Detalhes técnicos: ocultos"), this); technical_->setVisible(false); technical_->setWordWrap(true); root->addWidget(technical_);
    auto* actions = new QHBoxLayout();
    configure_ = new QPushButton(tr("Configurar proteção"), this);
    changeCode_ = new QPushButton(tr("Trocar código"), this); changeCode_->setEnabled(false); changeCode_->setToolTip(tr("Esta versão não possui um fluxo seguro para trocar o código."));
    revoke_ = new QPushButton(tr("Revogar dispositivo"), this); revoke_->setEnabled(false);
    actions->addWidget(configure_); actions->addWidget(changeCode_); actions->addWidget(revoke_); root->addLayout(actions);
    connect(configure_, &QPushButton::clicked, this, [this] { emit protectionRevoked(false); });
    connect(revoke_, &QPushButton::clicked, this, [this] {
        if (facts_.pairedUuid.isNull()) return;
        if (QMessageBox::question(this, tr("Revogar dispositivo"), tr("Revogar o dispositivo pareado? A conexão atual será encerrada.")) != QMessageBox::Yes) return;
        const bool ok = registry_.remove(facts_.pairedUuid);
        if (ok) { facts_ = {}; refresh(); }
        emit protectionRevoked(ok);
    });
    refresh();
}
void ProtectionPanel::setFacts(const ProtectionFacts& facts) { facts_ = facts; refresh(); }
void ProtectionPanel::setConfigureHandler(const std::function<void()>& h) { disconnect(configure_, nullptr, this, nullptr); connect(configure_, &QPushButton::clicked, this, h); }
void ProtectionPanel::setRevokeHandler(const std::function<bool(const QUuid&)>& h)
{
    disconnect(revoke_, nullptr, this, nullptr);
    connect(revoke_, &QPushButton::clicked, this, [this, h] {
        if (facts_.pairedUuid.isNull()) return;
        if (QMessageBox::question(this, tr("Revogar dispositivo"), tr("Revogar o dispositivo pareado? A conexão atual será encerrada.")) != QMessageBox::Yes) return;
        const bool ok = h ? h(facts_.pairedUuid) : false;
        if (ok) { facts_ = {}; refresh(); }
        emit protectionRevoked(ok);
    });
}
void ProtectionPanel::refresh() { state_ = stateFor(facts_); stateLabel_->setText(stateLabel(state_)); explanation_->setText(stateExplanation(state_)); revoke_->setEnabled(!facts_.pairedUuid.isNull()); technical_->setText(facts_.tlsActive ? tr("Detalhes técnicos: conexão TLS ativa; nenhum segredo é exibido.") : tr("Detalhes técnicos: conexão TLS não confirmada.")); }
