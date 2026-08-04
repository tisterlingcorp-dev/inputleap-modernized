#include "ZeroconfMetadata.h"

#include <QStringDecoder>
#include <QRegularExpression>
#include <algorithm>

namespace {
QString osName(ZeroconfOsFamily value) { switch(value) { case ZeroconfOsFamily::Windows:return "windows"; case ZeroconfOsFamily::MacOS:return "macos"; case ZeroconfOsFamily::Linux:return "linux"; case ZeroconfOsFamily::Other:return "other"; } return {}; }
QString roleName(ZeroconfRole value) { switch(value) { case ZeroconfRole::Server:return "server"; case ZeroconfRole::Client:return "client"; case ZeroconfRole::Dual:return "dual"; } return {}; }
QString capabilityName(ZeroconfCapability value) { switch(value) { case ZeroconfCapability::Keyboard:return "keyboard"; case ZeroconfCapability::Mouse:return "mouse"; case ZeroconfCapability::Clipboard:return "clipboard"; case ZeroconfCapability::FileTransfer:return "file-transfer"; } return {}; }

template<class T, class F> QString joined(const QSet<T>& values, F convert)
{
    QStringList result;
    for (const auto& value : values) result.append(convert(value));
    std::sort(result.begin(), result.end());
    return result.join(',');
}
bool safeText(const QString& value, qsizetype maximum, bool emptyAllowed = false)
{
    const QByteArray utf8 = value.toUtf8();
    return (emptyAllowed || !value.isEmpty()) && utf8.size() <= maximum && !value.contains('\n') && !value.contains('\r') && !value.contains(QChar::Null);
}
std::optional<int> strictInt(const QByteArray& value)
{
    if (value.isEmpty() || (value.size() > 1 && value.startsWith('0'))) return {};
    bool ok = false; const int result = value.toInt(&ok);
    if (!ok) return {};
    return result;
}
ZeroconfParseResult malformed(const QString& detail) { return {ZeroconfParseStatus::Malformed, {}, detail}; }
}

ZeroconfSerializeResult ZeroconfMetadataCodec::serialize(const ZeroconfMetadata& m)
{
    if (m.uuid.isNull()) return {false, {}, "UUID ausente"};
    if (!safeText(m.technicalName, 128) || !safeText(m.friendlyName, 192, true) || !safeText(m.inputLeapVersion, 64))
        return {false, {}, "Campo textual inválido ou grande demais"};
    if (!m.transferPort || (m.role != ZeroconfRole::Client && !m.controlPort)) return {false, {}, "Porta fora do intervalo"};
    if (osName(m.osFamily).isEmpty() || roleName(m.role).isEmpty()) return {false, {}, "Enum inválido"};
    for (const auto capability : m.capabilities) if (capabilityName(capability).isEmpty()) return {false, {}, "Enum inválido"};
    for (const auto& feature : m.features)
        if (!safeText(feature, 48) || feature.contains(',') || !feature.contains(QRegularExpression("^[a-z0-9-]+$")))
            return {false, {}, "Recurso inválido"};
    const QString caps = joined(m.capabilities, capabilityName);
    if (caps.isEmpty()) return {false, {}, "Capacidade ausente"};
    const QList<QPair<QByteArray,QByteArray>> fields = {
        {"sv", QByteArray::number(ZeroconfSchemaVersion)}, {"pv", QByteArray::number(ZeroconfProtocolVersion)},
        {"uuid", m.uuid.toString(QUuid::WithoutBraces).toLower().toUtf8()}, {"name", m.technicalName.toUtf8()},
        {"friendly", m.friendlyName.toUtf8()}, {"os", osName(m.osFamily).toUtf8()}, {"ver", m.inputLeapVersion.toUtf8()},
        {"role", roleName(m.role).toUtf8()}, {"cap", caps.toUtf8()}, {"cp", QByteArray::number(m.controlPort)},
        {"tp", QByteArray::number(m.transferPort)}, {"feat", joined(m.features, [](const QString& s){ return s; }).toUtf8()}
    };
    QList<QPair<QByteArray,QByteArray>> outputFields = fields;
    if (!m.protocolVersions.isEmpty()) outputFields.append({"cv", CapabilityNegotiationPolicy::encodeVersions(m.protocolVersions).toUtf8()});
    if (m.pairingPort) outputFields.append({"pp", QByteArray::number(m.pairingPort)});
    QByteArray txt;
    for (const auto& [key,value] : outputFields) {
        if (value.size() > 255) return {false, {}, "Campo TXT grande demais"};
        if (!txt.isEmpty()) txt += '\n';
        txt += key + '=' + value;
    }
    if (txt.size() > maximumTxtBytes()) return {false, {}, "TXT total grande demais"};
    return {true, txt, {}};
}

ZeroconfParseResult ZeroconfMetadataCodec::parse(const QByteArray& txt)
{
    if (txt.isEmpty()) return {ZeroconfParseStatus::Legacy, {}, "Anúncio legado sem metadados"};
    if (txt.size() > maximumTxtBytes()) return malformed("TXT total grande demais");
    QStringDecoder decoder(QStringDecoder::Utf8);
    const QString decoded = decoder.decode(txt);
    if (decoder.hasError()) return malformed("UTF-8 inválido");
    QHash<QByteArray,QByteArray> fields;
    for (const QByteArray& line : txt.split('\n')) {
        const qsizetype equals = line.indexOf('=');
        if (equals <= 0 || line.size() - equals - 1 > 255) return malformed("Registro TXT inválido");
        const QByteArray key = line.left(equals), value = line.mid(equals + 1);
        if (fields.contains(key)) return malformed("Chave TXT duplicada");
        fields.insert(key, value);
    }
    if (!fields.contains("sv") && !fields.contains("uuid")) return {ZeroconfParseStatus::Legacy, {}, "Anúncio legado sem UUID"};
    const QByteArray uuidText = fields.value("uuid");
    const QUuid uuid(QString::fromLatin1(uuidText));
    if (uuid.isNull() || uuidText != uuid.toString(QUuid::WithoutBraces).toLower().toLatin1()) return malformed("UUID não canônico");
    const auto sv = strictInt(fields.value("sv")), pv = strictInt(fields.value("pv"));
    if (!sv || !pv) return malformed("Versão inválida");
    if (*sv != ZeroconfSchemaVersion || *pv != ZeroconfProtocolVersion) {
        ZeroconfMetadata incompatible;
        incompatible.uuid = uuid;
        const QString name = QString::fromUtf8(fields.value("name"));
        const QString friendly = QString::fromUtf8(fields.value("friendly"));
        if (safeText(name, 128, true)) incompatible.technicalName = name;
        if (safeText(friendly, 192, true)) incompatible.friendlyName = friendly;
        return {ZeroconfParseStatus::Incompatible, incompatible, "Versão de protocolo incompatível"};
    }
    const QList<QByteArray> required = {"name","os","ver","role","cap","cp","tp","feat"};
    for (const auto& key : required) if (!fields.contains(key)) return malformed("Campo obrigatório ausente: " + QString::fromLatin1(key));
    ZeroconfMetadata m; m.uuid = uuid; m.technicalName = QString::fromUtf8(fields["name"]); m.friendlyName = QString::fromUtf8(fields.value("friendly")); m.inputLeapVersion = QString::fromUtf8(fields["ver"]);
    if (!safeText(m.technicalName,128) || !safeText(m.friendlyName,192,true) || !safeText(m.inputLeapVersion,64)) return malformed("Campo textual inválido");
    const QHash<QByteArray,ZeroconfOsFamily> os = {{"windows",ZeroconfOsFamily::Windows},{"macos",ZeroconfOsFamily::MacOS},{"linux",ZeroconfOsFamily::Linux},{"other",ZeroconfOsFamily::Other}};
    const QHash<QByteArray,ZeroconfRole> roles = {{"server",ZeroconfRole::Server},{"client",ZeroconfRole::Client},{"dual",ZeroconfRole::Dual}};
    if (!os.contains(fields["os"]) || !roles.contains(fields["role"])) return malformed("Enum inválido");
    m.osFamily=os[fields["os"]]; m.role=roles[fields["role"]];
    const QHash<QByteArray,ZeroconfCapability> caps={{"keyboard",ZeroconfCapability::Keyboard},{"mouse",ZeroconfCapability::Mouse},{"clipboard",ZeroconfCapability::Clipboard},{"file-transfer",ZeroconfCapability::FileTransfer}};
    for (const auto& cap : fields["cap"].split(',')) { if (cap.isEmpty() || !caps.contains(cap) || m.capabilities.contains(caps[cap])) return malformed("Capacidade inválida ou duplicada"); m.capabilities.insert(caps[cap]); }
    if (m.capabilities.isEmpty()) return malformed("Capacidade ausente");
    const auto cp=strictInt(fields["cp"]), tp=strictInt(fields["tp"]);
    if (!cp || !tp || *cp<0 || *cp>65535 || *tp<1 || *tp>65535 || (m.role != ZeroconfRole::Client && *cp == 0) || (m.role == ZeroconfRole::Client && *cp != 0)) return malformed("Porta inválida");
    m.controlPort=quint16(*cp); m.transferPort=quint16(*tp);
    if (fields.contains("pp")) {
        const auto pp=strictInt(fields["pp"]);
        if (!pp || *pp < 1 || *pp > 65535) return malformed("Porta de pareamento inválida");
        m.pairingPort=quint16(*pp);
    }
    if (!fields["feat"].isEmpty()) for (const auto& item : fields["feat"].split(',')) { const QString feature=QString::fromLatin1(item); if (!safeText(feature,48) || !feature.contains(QRegularExpression("^[a-z0-9-]+$"))) return malformed("Recurso inválido"); m.features.insert(feature); }
    if (fields.contains("cv")) {
        const auto versions=CapabilityNegotiationPolicy::parseVersions(QString::fromLatin1(fields["cv"]));
        if (!versions || !versions->contains(CapabilityId::Control)) return malformed("Versões de capacidades inválidas ou sem controle");
        m.protocolVersions=*versions;
    }
    return {ZeroconfParseStatus::Compatible, m, {}};
}

DnsSdTxtEncodeResult DnsSdTxtRecordCodec::encode(const QList<QByteArray>& entries)
{
    QByteArray wire;
    for (const auto& entry : entries) {
        if (entry.isEmpty() || entry.size() > 255 || wire.size() + entry.size() + 1 > ZeroconfMetadataCodec::maximumTxtBytes())
            return {false, {}, "Entrada TXT DNS-SD inválida"};
        wire.append(char(entry.size())); wire.append(entry);
    }
    return {true, wire, {}};
}

DnsSdTxtEncodeResult DnsSdTxtRecordCodec::fromCanonical(const QByteArray& canonical)
{
    return encode(canonical.isEmpty() ? QList<QByteArray>{} : canonical.split('\n'));
}

ZeroconfParseResult DnsSdTxtRecordCodec::decode(const QByteArray& wire)
{
    if (wire.isEmpty()) return ZeroconfMetadataCodec::parse({});
    if (wire.size() > ZeroconfMetadataCodec::maximumTxtBytes()) return malformed("TXT wire grande demais");
    QList<QByteArray> entries; QSet<QByteArray> keys;
    qsizetype offset = 0;
    while (offset < wire.size()) {
        const auto length = static_cast<unsigned char>(wire.at(offset++));
        if (!length || offset + length > wire.size()) return malformed("TXT wire truncado ou vazio");
        const QByteArray entry = wire.mid(offset, length); offset += length;
        const auto equals = entry.indexOf('=');
        if (equals <= 0) return malformed("Entrada TXT wire inválida");
        const auto key = entry.left(equals);
        if (keys.contains(key)) return malformed("Chave TXT duplicada");
        keys.insert(key); entries.append(entry);
    }
    return ZeroconfMetadataCodec::parse(entries.join('\n'));
}

ZeroconfDiscoveryCache::ZeroconfDiscoveryCache(Clock clock, qint64 ttlMs) : clock_(std::move(clock)), ttlMs_(ttlMs) {}
ZeroconfDiscoveryEvent ZeroconfDiscoveryCache::observe(const ZeroconfMetadata& metadata, const QString& address, quint32 interfaceIndex)
{
    if (metadata.uuid.isNull() || address.isEmpty() || !interfaceIndex || !clock_ || ttlMs_ <= 0) return ZeroconfDiscoveryEvent::Rejected;
    const qint64 now = clock_(); if (now < 0) return ZeroconfDiscoveryEvent::Rejected;
    const bool exists=devices_.contains(metadata.uuid);
    const bool changed = !exists || devices_[metadata.uuid].metadata != metadata ||
        !devices_[metadata.uuid].interfaceAddresses.value(interfaceIndex).contains(address);
    auto& item=devices_[metadata.uuid]; item.uuid=metadata.uuid; item.metadata=metadata;
    item.interfaceAddresses[interfaceIndex].insert(address); item.addressLastSeenMs[interfaceIndex][address]=now; item.interfaceLastSeenMs[interfaceIndex]=now;
    item.interfaces.clear(); for(auto i=item.interfaceLastSeenMs.cbegin();i!=item.interfaceLastSeenMs.cend();++i)item.interfaces.insert(i.key());
    item.addresses.clear(); for (const auto& values : item.interfaceAddresses) item.addresses.unite(values);
    item.lastSeenMs=now;
    if (!exists) return ZeroconfDiscoveryEvent::Found;
    return changed ? ZeroconfDiscoveryEvent::Updated : ZeroconfDiscoveryEvent::Refreshed;
}
std::optional<DiscoveredDeviceAdvertisement> ZeroconfDiscoveryCache::remove(const QUuid& uuid, quint32 interfaceIndex)
{
    auto it=devices_.find(uuid); if(it==devices_.end()) return {}; it->interfaceLastSeenMs.remove(interfaceIndex); it->interfaceAddresses.remove(interfaceIndex); it->addressLastSeenMs.remove(interfaceIndex); it->interfaces.remove(interfaceIndex); it->addresses.clear(); for(const auto& v:it->interfaceAddresses) it->addresses.unite(v); if(!it->interfaces.isEmpty()) return {}; const auto value=*it; devices_.erase(it); return value;
}
std::optional<DiscoveredDeviceAdvertisement> ZeroconfDiscoveryCache::removeAddress(const QUuid& uuid, const QString& address, quint32 interfaceIndex)
{
    auto it=devices_.find(uuid); if(it==devices_.end()) return {}; it->interfaceAddresses[interfaceIndex].remove(address); it->addressLastSeenMs[interfaceIndex].remove(address);
    if(it->interfaceAddresses[interfaceIndex].isEmpty()){it->interfaceAddresses.remove(interfaceIndex);it->addressLastSeenMs.remove(interfaceIndex);it->interfaceLastSeenMs.remove(interfaceIndex);it->interfaces.remove(interfaceIndex);}
    it->addresses.clear();for(const auto&v:it->interfaceAddresses)it->addresses.unite(v);if(!it->interfaces.isEmpty())return {};const auto value=*it;devices_.erase(it);return value;
}
QList<DiscoveredDeviceAdvertisement> ZeroconfDiscoveryCache::expire()
{
    QList<DiscoveredDeviceAdvertisement> lost; if(!clock_ || ttlMs_<=0) return lost; const qint64 now=clock_(); if(now<0) return lost;
    for(auto it=devices_.begin();it!=devices_.end();) { const auto interfaces=it->addressLastSeenMs.keys(); for(auto i:interfaces){const auto addresses=it->addressLastSeenMs[i].keys();for(const auto&a:addresses)if(now-it->addressLastSeenMs[i][a]>=ttlMs_){it->addressLastSeenMs[i].remove(a);it->interfaceAddresses[i].remove(a);}if(it->interfaceAddresses[i].isEmpty()){it->addressLastSeenMs.remove(i);it->interfaceAddresses.remove(i);it->interfaceLastSeenMs.remove(i);it->interfaces.remove(i);}else{qint64 newest=0;for(auto seen:it->addressLastSeenMs[i])newest=std::max(newest,seen);it->interfaceLastSeenMs[i]=newest;}} it->addresses.clear();for(const auto&v:it->interfaceAddresses)it->addresses.unite(v);it->lastSeenMs=0;for(auto seen:it->interfaceLastSeenMs)it->lastSeenMs=std::max(it->lastSeenMs,seen); if(it->interfaces.isEmpty()){lost.append(*it);it=devices_.erase(it);}else ++it;} return lost;
}
QList<DiscoveredDeviceAdvertisement> ZeroconfDiscoveryCache::devices() const { auto result=devices_.values(); std::sort(result.begin(),result.end(),[](const auto&a,const auto&b){return a.uuid.toString()<b.uuid.toString();}); return result; }
