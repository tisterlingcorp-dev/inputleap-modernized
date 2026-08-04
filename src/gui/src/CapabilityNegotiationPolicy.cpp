#include "CapabilityNegotiationPolicy.h"

#include <QRegularExpression>
#include <algorithm>

namespace {
NegotiationDecision blocked(QString reason, CapabilityId id, const ProtocolVersion* local = nullptr, const ProtocolVersion* remote = nullptr)
{
    QString technical = QStringLiteral("capacidade=%1").arg(CapabilityNegotiationPolicy::capabilityName(id));
    if (local) technical += QStringLiteral("; local=%1").arg(local->toString());
    if (remote) technical += QStringLiteral("; remoto=%1").arg(remote->toString());
    return NegotiationDecision{NegotiationStatus::SecurityBlocked, std::move(reason), technical, false, std::nullopt};
}
}

std::optional<ProtocolVersion> ProtocolVersion::parse(const QString& text)
{
    static const QRegularExpression expression(QStringLiteral("^(0|[1-9][0-9]{0,3})\\.(0|[1-9][0-9]{0,3})$"));
    const auto match = expression.match(text);
    if (!match.hasMatch()) return std::nullopt;
    bool majorOk=false, minorOk=false;
    const int major=match.captured(1).toInt(&majorOk), minor=match.captured(2).toInt(&minorOk);
    if (!majorOk || !minorOk || major < 1) return std::nullopt;
    return ProtocolVersion{major,minor};
}
QString ProtocolVersion::toString() const { return QStringLiteral("%1.%2").arg(major).arg(minor); }

NegotiationDecision CapabilityNegotiationSnapshot::capability(CapabilityId id) const
{
    if (id == CapabilityId::Control) return base;
    return capabilities.value(id, {NegotiationStatus::Unknown, QStringLiteral("Recurso não anunciado pelo outro computador."),
                                    QStringLiteral("capacidade=%1; versão remota=ausente").arg(CapabilityNegotiationPolicy::capabilityName(id))});
}

CapabilityNegotiationPolicy::CapabilityNegotiationPolicy()
    : local_({{CapabilityId::Control,{{1,0},{1,0},false}},
              {CapabilityId::FileTransfer,{{1,0},{1,2},false}},
              {CapabilityId::Pairing,{{1,0},{1,0},true}},
              {CapabilityId::Monitor,{{1,0},{1,0},true}}}) {}
CapabilityNegotiationPolicy::CapabilityNegotiationPolicy(QMap<CapabilityId, CapabilitySupport> local) : local_(std::move(local)) {}

QString CapabilityNegotiationPolicy::capabilityName(CapabilityId id)
{
    switch(id) { case CapabilityId::Control:return QStringLiteral("control"); case CapabilityId::FileTransfer:return QStringLiteral("file-transfer");
    case CapabilityId::Pairing:return QStringLiteral("pairing"); case CapabilityId::Monitor:return QStringLiteral("monitor"); }
    return {};
}

NegotiationDecision CapabilityNegotiationPolicy::decide(CapabilityId id, const ProtocolVersion& remote, bool authenticated) const
{
    if (!local_.contains(id)) return NegotiationDecision{NegotiationStatus::UpgradeLocal, QStringLiteral("Atualização necessária — atualize este computador."),
                                      QStringLiteral("capacidade=%1; local=ausente; remoto=%2").arg(capabilityName(id),remote.toString()), false, std::nullopt};
    const auto support=local_.value(id);
    const QString tech=QStringLiteral("capacidade=%1; local=%2..%3; remoto=%4").arg(capabilityName(id),support.minimum.toString(),support.maximum.toString(),remote.toString());
    if (remote.major > support.maximum.major)
        return NegotiationDecision{NegotiationStatus::UpgradeLocal,QStringLiteral("Atualização necessária — atualize este computador."),tech, false, std::nullopt};
    if (remote.major < support.minimum.major)
        return support.securitySensitive ? NegotiationDecision{NegotiationStatus::SecurityBlocked,QStringLiteral("Recurso bloqueado por segurança; atualize o outro computador."),tech, false, std::nullopt}
                                         : NegotiationDecision{NegotiationStatus::UpgradeRemote,QStringLiteral("Atualização necessária — atualize o outro computador."),tech, false, std::nullopt};
    if (remote.minor < support.minimum.minor)
        return support.securitySensitive ? NegotiationDecision{NegotiationStatus::SecurityBlocked,QStringLiteral("Recurso bloqueado por segurança; atualize o outro computador."),tech, false, std::nullopt}
                                         : NegotiationDecision{NegotiationStatus::UpgradeRemote,QStringLiteral("Atualização necessária — atualize o outro computador."),tech, false, std::nullopt};
    if (support.securitySensitive && !authenticated)
        return NegotiationDecision{NegotiationStatus::SecurityBlocked,QStringLiteral("Confirme este recurso em uma conexão autenticada."),tech+QStringLiteral("; anúncio DNS-SD não autenticado"),true, std::nullopt};
    NegotiationDecision result;
    result.status=remote.minor==support.maximum.minor?NegotiationStatus::Supported:NegotiationStatus::Degraded;
    result.reason=result.status==NegotiationStatus::Supported?QStringLiteral("Compatível."):QStringLiteral("Compatível com alguns recursos limitados.");
    result.technical=tech;
    result.negotiatedVersion=ProtocolVersion{remote.major,(std::min)(remote.minor,support.maximum.minor)};
    return result;
}

CapabilityNegotiationSnapshot CapabilityNegotiationPolicy::negotiate(const CapabilityAdvertisement& ad) const
{
    CapabilityNegotiationSnapshot result; result.uuid=ad.uuid;
    if (ad.uuid.isNull() || !ad.metadataValid) {
        result.base=blocked(QStringLiteral("Conexão bloqueada: anúncio inválido ou conflitante."),CapabilityId::Control);
        for (auto id:{CapabilityId::FileTransfer,CapabilityId::Pairing,CapabilityId::Monitor}) result.capabilities[id]=result.base;
        return result;
    }
    if (ad.legacy) {
        if (ad.legacyAppVersion == QStringLiteral("3.1.0") || ad.legacyAppVersion == QStringLiteral("3.1.0-modernized")) {
            result.base=NegotiationDecision{NegotiationStatus::Degraded,QStringLiteral("Compatibilidade básica com InputLeap 3.1.0; recursos novos ficam desativados."),QStringLiteral("baseline legado seguro exato=3.1.0; control=1.0"), false, std::nullopt};
        } else result.base=blocked(QStringLiteral("Conexão bloqueada por segurança; atualize o outro computador."),CapabilityId::Control);
        return result;
    }
    if (!ad.versions.contains(CapabilityId::Control)) {
        result.base=blocked(QStringLiteral("Conexão bloqueada: versão de controle não informada."),CapabilityId::Control);
    } else result.base=decide(CapabilityId::Control,ad.versions.value(CapabilityId::Control),true);
    for (auto id:{CapabilityId::FileTransfer,CapabilityId::Pairing,CapabilityId::Monitor}) {
        if (ad.claimed.contains(id) && !ad.versions.contains(id)) {
            result.capabilities[id]=blocked(QStringLiteral("Recurso bloqueado: foi anunciado sem versão obrigatória."),id);
        } else if (!ad.claimed.contains(id) && ad.versions.contains(id)) {
            result.capabilities[id]=blocked(QStringLiteral("Recurso bloqueado: versão anunciada sem a capacidade correspondente."),id);
        } else if (!ad.versions.contains(id)) {
            result.capabilities[id]=NegotiationDecision{NegotiationStatus::Unknown,QStringLiteral("Recurso não anunciado pelo outro computador."),QStringLiteral("capacidade=%1; remoto=ausente").arg(capabilityName(id)), false, std::nullopt};
        } else if (!result.base.allowed()) {
            result.capabilities[id]=blocked(QStringLiteral("Recurso bloqueado: depende de uma conexão de controle compatível."),id);
        } else result.capabilities[id]=decide(id,ad.versions.value(id),ad.authenticated.contains(id));
    }
    return result;
}

QString CapabilityNegotiationPolicy::encodeVersions(const QMap<CapabilityId, ProtocolVersion>& versions)
{
    QStringList fields;
    for(auto it=versions.cbegin();it!=versions.cend();++it) fields << capabilityName(it.key())+QLatin1Char(':')+it.value().toString();
    fields.sort(Qt::CaseSensitive); return fields.join(QLatin1Char(','));
}
std::optional<QMap<CapabilityId, ProtocolVersion>> CapabilityNegotiationPolicy::parseVersions(const QString& encoded)
{
    if (encoded.isEmpty() || encoded.toUtf8().size()>240) return std::nullopt;
    const QHash<QString,CapabilityId> names={{"control",CapabilityId::Control},{"file-transfer",CapabilityId::FileTransfer},{"pairing",CapabilityId::Pairing},{"monitor",CapabilityId::Monitor}};
    QMap<CapabilityId,ProtocolVersion> result;
    for(const auto& field:encoded.split(',')) { const int colon=field.indexOf(':'); if(colon<=0||field.indexOf(':',colon+1)>=0)return std::nullopt;
        const auto name=field.left(colon); const auto version=ProtocolVersion::parse(field.mid(colon+1));
        if(!names.contains(name)||!version||result.contains(names.value(name)))return std::nullopt; result.insert(names.value(name),*version); }
    return result;
}

CapabilityNegotiationStore::CapabilityNegotiationStore(CapabilityNegotiationPolicy policy):policy_(std::move(policy)){}
void CapabilityNegotiationStore::replace(const CapabilityAdvertisement& ad){if(ad.uuid.isNull())return;snapshots_[ad.uuid]=policy_.negotiate(ad);}
void CapabilityNegotiationStore::remove(const QUuid& uuid){snapshots_.remove(uuid);}
std::optional<CapabilityNegotiationSnapshot> CapabilityNegotiationStore::snapshot(const QUuid& uuid)const{auto i=snapshots_.constFind(uuid);return i==snapshots_.cend()?std::nullopt:std::optional(i.value());}
bool CapabilityNegotiationStore::revalidate(const QUuid& uuid,CapabilityId capability)const{const auto current=snapshot(uuid);return current&&(capability==CapabilityId::Control?current->baseConnectionAllowed():current->capabilityAllowed(capability));}
