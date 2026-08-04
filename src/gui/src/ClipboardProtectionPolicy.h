#pragma once

#include <QString>
#include <QStringList>

class ClipboardProtectionPolicy final
{
public:
    struct Metadata {
        // True only when the platform adapter positively answered the query.
        bool hasPasswordSignal = false;
        bool isPassword = false;
        QString ownerProcessPath;
        quint64 ownerProcessId = 0;
    };
    enum class DecisionReason { Accepted, Paused, PasswordField, UnknownSensitiveSource, ExcludedApplication };

    void setPaused(bool paused) { paused_ = paused; }
    bool paused() const { return paused_; }
    void setExcludedApplications(QStringList paths);
    const QStringList& excludedApplications() const { return excludedApplications_; }
    bool accept(const Metadata& metadata, const QString& content);
    DecisionReason reason() const { return reason_; }
    QString stateLabel() const;

private:
    bool paused_ = false;
    QStringList excludedApplications_;
    DecisionReason reason_ = DecisionReason::Accepted;
};
