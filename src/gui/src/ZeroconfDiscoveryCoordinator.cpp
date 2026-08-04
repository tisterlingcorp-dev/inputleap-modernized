#include "ZeroconfDiscoveryCoordinator.h"

ZeroconfDiscoveryCoordinator::Token ZeroconfDiscoveryCoordinator::begin(
    const QString& key, const QString& serviceName, quint32 interfaceIndex)
{
    Pending pending;
    pending.token = ++nextToken_;
    pending.serviceName = serviceName;
    pending.interfaceIndex = interfaceIndex;
    pending_.insert(key, pending);
    return pending.token;
}

std::optional<QUuid> ZeroconfDiscoveryCoordinator::cancel(const QString& key)
{
    const auto it = pending_.find(key);
    if (it == pending_.end()) return std::nullopt;
    const QUuid uuid = it->uuid;
    pending_.erase(it);
    return uuid.isNull() ? std::nullopt : std::optional<QUuid>(uuid);
}

bool ZeroconfDiscoveryCoordinator::active(const QString& key, Token token) const
{
    const auto it = pending_.constFind(key);
    return it != pending_.cend() && it->token == token;
}

bool ZeroconfDiscoveryCoordinator::setResolved(
    const QString& key, Token token, const QByteArray& wireTxt, quint16 port)
{
    auto it = pending_.find(key);
    if (it == pending_.end() || it->token != token || it->stage != Pending::Stage::Resolving) return false;
    it->wireTxt = wireTxt;
    it->port = port;
    it->stage = Pending::Stage::AddressLookup;
    return true;
}

ZeroconfDiscoveryCoordinator::Decision ZeroconfDiscoveryCoordinator::address(
    const QString& key, Token token, bool add, const QString& address, quint32 ttl)
{
    auto it = pending_.find(key);
    if (it == pending_.end() || it->token != token || it->stage != Pending::Stage::AddressLookup) return {};
    const auto parsed = DnsSdTxtRecordCodec::decode(it->wireTxt);
    if (parsed.status == ZeroconfParseStatus::Legacy)
        return {Route::Legacy, {}, parsed.detail};
    if (parsed.status == ZeroconfParseStatus::Incompatible) {
        if (!parsed.metadata || address.isEmpty() || (add && ttl == 0))
            return {Route::InvalidAddress, {}, QStringLiteral("TTL/endereço DNS-SD inválido")};
        ZeroconfMetadata metadata = *parsed.metadata;
        if (metadata.technicalName.isEmpty()) metadata.technicalName = it->serviceName;
        it->uuid = metadata.uuid;
        return {Route::Incompatible, metadata, parsed.detail};
    }
    if (parsed.status == ZeroconfParseStatus::Malformed)
        return {Route::Malformed, {}, parsed.detail};
    const bool validPort = parsed.metadata && (parsed.metadata->role == ZeroconfRole::Client ? it->port != 0 : it->port == parsed.metadata->controlPort);
    if (!parsed.metadata || (add && ttl == 0) || address.isEmpty() || !validPort)
        return {Route::InvalidAddress, {}, QStringLiteral("Porta/TTL/endereço DNS-SD inválido")};
    it->uuid = parsed.metadata->uuid;
    return {add ? Route::CompatibleAdd : Route::CompatibleRemove, parsed.metadata, {}};
}
