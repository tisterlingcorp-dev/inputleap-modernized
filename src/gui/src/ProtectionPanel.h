#pragma once

#include "DevicePermissions.h"
#include <QFrame>
#include <QUuid>
#include <functional>

class DeviceRegistry;
class QLabel;
class QPushButton;
class QToolButton;

struct ProtectionFacts {
    QUuid pairedUuid;
    bool pairedSessionKey = false;
    bool tlsActive = false;
    bool receiverGate = false;
    DevicePermissions::Mask permissions = DevicePermissions::None;
};

class ProtectionPanel final : public QFrame {
    Q_OBJECT
public:
    enum class State { Complete, Attention, Unpaired };
    static State stateFor(const ProtectionFacts& facts);
    static QString stateLabel(State state);
    static QString badgeLabel(const ProtectionFacts& facts);
    static QString stateExplanation(State state);

    ProtectionPanel(DeviceRegistry& registry, QWidget* parent = nullptr);
    void setFacts(const ProtectionFacts& facts);
    State state() const { return state_; }
    QPushButton* configureButton() const { return configure_; }
    QPushButton* changeCodeButton() const { return changeCode_; }
    QPushButton* revokeButton() const { return revoke_; }
    QLabel* stateLabelWidget() const { return stateLabel_; }
    void setConfigureHandler(const std::function<void()>& handler);
    void setRevokeHandler(const std::function<bool(const QUuid&)>& handler);

signals:
    void protectionRevoked(bool success);

private:
    void refresh();
    DeviceRegistry& registry_;
    ProtectionFacts facts_;
    State state_ = State::Unpaired;
    QLabel* stateLabel_ = nullptr;
    QLabel* explanation_ = nullptr;
    QLabel* technical_ = nullptr;
    QPushButton* configure_ = nullptr;
    QPushButton* changeCode_ = nullptr;
    QPushButton* revoke_ = nullptr;
};
