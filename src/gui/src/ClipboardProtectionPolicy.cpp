#include "ClipboardProtectionPolicy.h"

#include <QDir>

void ClipboardProtectionPolicy::setExcludedApplications(QStringList paths)
{
    excludedApplications_.clear();
    for (const QString& path : paths) {
        const QString cleaned = QDir::cleanPath(path).toCaseFolded();
        if (!cleaned.isEmpty() && QDir::isAbsolutePath(path) && !excludedApplications_.contains(cleaned))
            excludedApplications_.append(cleaned);
    }
}

bool ClipboardProtectionPolicy::accept(const Metadata& metadata, const QString& content)
{
    Q_UNUSED(content); // Never infer sensitivity from textual content.
    if (paused_) { reason_ = DecisionReason::Paused; return false; }
    if (!metadata.hasPasswordSignal) { reason_ = DecisionReason::UnknownSensitiveSource; return false; }
    if (metadata.isPassword) { reason_ = DecisionReason::PasswordField; return false; }
    if (!metadata.ownerProcessPath.isEmpty() &&
        excludedApplications_.contains(QDir::cleanPath(metadata.ownerProcessPath).toCaseFolded())) {
        reason_ = DecisionReason::ExcludedApplication;
        return false;
    }
    reason_ = DecisionReason::Accepted;
    return true;
}

QString ClipboardProtectionPolicy::stateLabel() const
{
    return paused_ ? QStringLiteral("Pausado") : QStringLiteral("Ativo");
}
