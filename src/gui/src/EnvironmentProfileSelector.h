/* InputLeap -- reusable manual environment profile selector. */
#pragma once

#include "EnvironmentProfile.h"

#include <QFrame>
#include <QString>

#include <optional>

class QComboBox;
class QEvent;
class QLabel;
class QPushButton;

class EnvironmentProfileSelector final : public QFrame
{
    Q_OBJECT

public:
    explicit EnvironmentProfileSelector(QWidget* parent = nullptr);

    void setActiveKind(EnvironmentProfile::Kind kind);
    void setSwitchEnabled(bool enabled, const QString& reason = {});

Q_SIGNALS:
    void applyRequested(EnvironmentProfile::Kind kind);
    void captureRequested(EnvironmentProfile::Kind kind);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    bool selectedKind(EnvironmentProfile::Kind* kind) const;
    void refreshStatus();

    QComboBox* combo_ = nullptr;
    QPushButton* applyButton_ = nullptr;
    QPushButton* captureButton_ = nullptr;
    QLabel* status_ = nullptr;
    std::optional<EnvironmentProfile::Kind> activeKind_;
    bool selectionTouched_ = false;
    bool switchEnabled_ = true;
    QString blockReason_;
};
