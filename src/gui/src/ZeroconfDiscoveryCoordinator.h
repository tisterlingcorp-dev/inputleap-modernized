#pragma once

#include "ZeroconfMetadata.h"

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QUuid>
#include <optional>

class ZeroconfDiscoveryCoordinator
{
public:
    using Token = quint64;
    enum class Route { Ignored, CompatibleAdd, CompatibleRemove, Legacy, Incompatible, Malformed, InvalidAddress };
    struct Decision {
        Route route = Route::Ignored;
        std::optional<ZeroconfMetadata> metadata;
        QString detail;
    };

    Token begin(const QString& key, const QString& serviceName, quint32 interfaceIndex);
    std::optional<QUuid> cancel(const QString& key);
    bool setResolved(const QString& key, Token token, const QByteArray& wireTxt, quint16 port);
    Decision address(const QString& key, Token token, bool add, const QString& address, quint32 ttl);
    bool active(const QString& key, Token token) const;
    qsizetype pendingCount() const { return pending_.size(); }

private:
    struct Pending {
        enum class Stage { Resolving, AddressLookup, Cancelled };
        Token token = 0;
        QString serviceName;
        quint32 interfaceIndex = 0;
        QByteArray wireTxt;
        quint16 port = 0;
        QUuid uuid;
        Stage stage = Stage::Resolving;
    };
    Token nextToken_ = 0;
    QHash<QString, Pending> pending_;
};
