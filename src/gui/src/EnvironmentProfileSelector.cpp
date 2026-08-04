/* InputLeap -- reusable manual environment profile selector. */
#include "EnvironmentProfileSelector.h"

#include <QComboBox>
#include <QEvent>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMetaType>
#include <QPushButton>
#include <QSignalBlocker>
#include <QVariant>
#include <QVBoxLayout>

EnvironmentProfileSelector::EnvironmentProfileSelector(QWidget* parent) : QFrame(parent)
{
    setObjectName(QStringLiteral("environmentProfileSelector"));
    setFrameShape(QFrame::StyledPanel);
    setAccessibleName(tr("Seletor de perfil de ambiente"));
    setAccessibleDescription(tr("Escolha um perfil e confirme manualmente se deseja aplicá-lo ou salvar o estado atual."));

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 10, 12, 10);
    root->setSpacing(8);

    auto* selectionRow = new QHBoxLayout;
    selectionRow->setSpacing(8);

    combo_ = new QComboBox(this);
    combo_->setObjectName(QStringLiteral("environmentProfileCombo"));
    combo_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    combo_->setAccessibleName(tr("Perfil de ambiente desejado"));
    combo_->setAccessibleDescription(
        tr("Seleciona um perfil pendente sem aplicá-lo automaticamente; a seleção permanece disponível enquanto as ações estão bloqueadas."));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        combo_->addItem(EnvironmentProfile::canonicalDisplayName(kind), static_cast<int>(kind));
    }
    selectionRow->addWidget(combo_, 1);

    applyButton_ = new QPushButton(tr("Aplicar"), this);
    applyButton_->setObjectName(QStringLiteral("applyEnvironmentProfileButton"));
    applyButton_->setAccessibleName(tr("Aplicar perfil selecionado"));
    applyButton_->setAccessibleDescription(tr("Aplica manualmente o perfil de ambiente selecionado."));
    applyButton_->installEventFilter(this);
    selectionRow->addWidget(applyButton_);
    root->addLayout(selectionRow);

    captureButton_ = new QPushButton(tr("Salvar estado atual neste perfil"), this);
    captureButton_->setObjectName(QStringLiteral("captureEnvironmentProfileButton"));
    captureButton_->setAccessibleName(tr("Salvar estado atual no perfil selecionado"));
    captureButton_->setAccessibleDescription(
        tr("Solicita salvar o layout, os dispositivos e os recursos atuais no perfil selecionado."));
    captureButton_->installEventFilter(this);
    root->addWidget(captureButton_);

    status_ = new QLabel(this);
    status_->setObjectName(QStringLiteral("environmentProfileStatus"));
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    status_->setAccessibleName(tr("Estado do perfil de ambiente"));
    root->addWidget(status_);

    connect(applyButton_, &QPushButton::clicked, this, [this] {
        EnvironmentProfile::Kind kind;
        if (selectedKind(&kind)) {
            emit applyRequested(kind);
        }
    });
    connect(captureButton_, &QPushButton::clicked, this, [this] {
        EnvironmentProfile::Kind kind;
        if (selectedKind(&kind)) {
            emit captureRequested(kind);
        }
    });
    connect(combo_, &QComboBox::activated, this, [this](int) { selectionTouched_ = true; });

    refreshStatus();
}

bool EnvironmentProfileSelector::eventFilter(QObject* watched, QEvent* event)
{
    if ((watched == applyButton_ || watched == captureButton_) && event->type() == QEvent::KeyPress) {
        const auto* keyEvent = static_cast<QKeyEvent*>(event);
        if ((keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) &&
            static_cast<QPushButton*>(watched)->isEnabled()) {
            static_cast<QPushButton*>(watched)->click();
            return true;
        }
    }
    return QFrame::eventFilter(watched, event);
}

void EnvironmentProfileSelector::setActiveKind(EnvironmentProfile::Kind kind)
{
    if (!EnvironmentProfile::canonicalKinds().contains(kind)) {
        return;
    }

    const bool hadActive = activeKind_.has_value();
    activeKind_ = kind;
    if (!hadActive && !selectionTouched_) {
        const int index = combo_->findData(static_cast<int>(kind));
        if (index >= 0) {
            const QSignalBlocker blocker(combo_);
            combo_->setCurrentIndex(index);
        }
    }
    refreshStatus();
}

void EnvironmentProfileSelector::setSwitchEnabled(bool enabled, const QString& reason)
{
    switchEnabled_ = enabled;
    blockReason_ = enabled ? QString() : reason.trimmed();
    if (!enabled && blockReason_.isEmpty()) {
        blockReason_ = tr("A troca de perfil está indisponível no momento.");
    }

    applyButton_->setEnabled(enabled);
    captureButton_->setEnabled(enabled);
    refreshStatus();
}

bool EnvironmentProfileSelector::selectedKind(EnvironmentProfile::Kind* kind) const
{
    if (kind == nullptr || combo_->currentIndex() < 0) {
        return false;
    }

    const QVariant itemData = combo_->currentData();
    if (!itemData.isValid() || itemData.metaType().id() != QMetaType::Int) {
        return false;
    }
    const int rawKind = itemData.toInt();
    const auto candidate = static_cast<EnvironmentProfile::Kind>(rawKind);
    if (!EnvironmentProfile::canonicalKinds().contains(candidate)) {
        return false;
    }

    *kind = candidate;
    return true;
}

void EnvironmentProfileSelector::refreshStatus()
{
    if (!switchEnabled_) {
        const QString text = tr("Troca de perfil bloqueada: %1").arg(blockReason_);
        status_->setText(text);
        status_->setAccessibleDescription(text);
        return;
    }

    if (!activeKind_.has_value()) {
        const QString text = tr("Perfil ativo ainda não disponível.");
        status_->setText(text);
        status_->setAccessibleDescription(text);
        return;
    }

    const QString profileName = EnvironmentProfile::canonicalDisplayName(*activeKind_);
    const QString text = tr("Perfil ativo: %1").arg(profileName);
    status_->setText(text);
    status_->setAccessibleDescription(
        tr("O perfil de ambiente ativo no momento é %1.").arg(profileName));
}
