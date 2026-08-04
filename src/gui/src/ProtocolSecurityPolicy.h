#pragma once
#include <QByteArray>
#include <QHostAddress>
#include <QSet>
#include <QUuid>
#include <functional>
#include <optional>
#include <mutex>

// Authenticated, short-lived capability authorization for post-pairing operations.
// Zeroconf remains discovery-only: it never authorizes a peer or a capability.
class ProtocolSecurityPolicy {
public:
    using Clock = std::function<qint64()>;
    explicit ProtocolSecurityPolicy(Clock clock);
    static std::optional<QString> canonicalEndpoint(const QString& endpoint);
    static std::optional<QString> canonicalEndpoint(const QHostAddress& address, quint16 port);

    std::optional<QByteArray> issue(const QUuid& peer, const QUuid& authenticatedPeer,
                                    const QString& endpoint, const QSet<QString>& capabilities,
                                    const QByteArray& sessionKey, qint64 lifetimeMs) const;
    bool accept(const QByteArray& token, const QUuid& peer, const QUuid& authenticatedPeer,
                const QString& endpoint, const QSet<QString>& requiredCapabilities,
                const QByteArray& sessionKey);
private:
    Clock clock_;
    mutable std::mutex mutex_;
    QSet<QByteArray> consumed_;
};
