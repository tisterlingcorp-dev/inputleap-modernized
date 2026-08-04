#pragma once

#include "DiagnosticsRemediationService.h"
#include "DiagnosticsService.h"
#include <QDateTime>
#include <QUuid>
#include <functional>

enum class SupportReportMode { Server, Client, Unknown };

struct SupportReportSnapshot {
    QString appVersion;
    QString osProductType;
    QString osProductVersion;
    QString cpuArchitecture;
    SupportReportMode mode = SupportReportMode::Unknown;
    DiagnosticsReport diagnostics;
    FirewallDetection firewall;
    QString coreState;
    QString peerState;
    QString endpoint;
    QString deviceDisplayName;
    QUuid peerUuid;
    QStringList recentErrors;
};

struct SupportReportPolicy {
    static constexpr int MaxUtf8Bytes = 64 * 1024;
    static constexpr int MaxFieldCharacters = 2048;
    static constexpr int MaxErrorCount = 32;
    bool privateMode = true;
};

class SupportReportBuilder {
public:
    using Clock = std::function<QDateTime()>;
    explicit SupportReportBuilder(Clock clock = {});
    QString build(const SupportReportSnapshot &snapshot, const SupportReportPolicy &policy = {}) const;
    static QString sanitize(const QString &value, bool privateMode);
private:
    Clock clock_;
};
