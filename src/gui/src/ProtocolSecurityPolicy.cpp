#include "ProtocolSecurityPolicy.h"
#include <QCryptographicHash>
#include <QHostAddress>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <openssl/hmac.h>
#include <algorithm>

namespace {
QByteArray mac(const QByteArray& key, const QByteArray& body) {
    if (key.size() != 32 || body.isEmpty()) return {};
    QByteArray out(32, Qt::Uninitialized); unsigned n = 0;
    if (!HMAC(EVP_sha256(), key.constData(), key.size(), reinterpret_cast<const unsigned char*>(body.constData()), size_t(body.size()), reinterpret_cast<unsigned char*>(out.data()), &n) || n != 32) return {};
    return out;
}
QByteArray canonical(const QUuid& peer, const QString& endpoint, const QSet<QString>& caps, qint64 issued, qint64 expires, const QByteArray& nonce) {
    QStringList sorted = caps.values(); std::sort(sorted.begin(), sorted.end());
    return QByteArray("inputleap-cap-v1\0") + peer.toString(QUuid::WithoutBraces).toLower().toUtf8() + '\0' + endpoint.toUtf8() + '\0' + sorted.join(',').toUtf8() + '\0' + QByteArray::number(issued) + '\0' + QByteArray::number(expires) + '\0' + nonce.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}
}
ProtocolSecurityPolicy::ProtocolSecurityPolicy(Clock clock) : clock_(std::move(clock)) {}

std::optional<QString> ProtocolSecurityPolicy::canonicalEndpoint(const QString& input) {
    const QString value = input.trimmed();
    if (value.isEmpty() || value.contains(QRegularExpression(QStringLiteral("[\\r\\n\\t ]")))) return {};
    QString host; quint16 port = 0; bool hasPort = false;
    if (value.startsWith('[')) {
        const int close = value.indexOf(']');
        if (close < 0) return {};
        host = value.mid(1, close - 1);
        if (value.size() > close + 1) {
            if (value.at(close + 1) != ':') return {};
            bool ok = false; const int p = value.mid(close + 2).toInt(&ok);
            if (!ok || p < 1 || p > 65535) return {}; port = quint16(p); hasPort = true;
        }
    } else {
        const int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) {
            bool ok = false; const int p = value.mid(colon + 1).toInt(&ok);
            if (!ok || p < 1 || p > 65535) return {};
            host = value.left(colon); port = quint16(p); hasPort = true;
        } else host = value;
    }
    QHostAddress address;
    if (!address.setAddress(host)) return {}; // hostnames and ambiguous forms fail closed
    QString result = address.toString().toLower();
    if (!address.scopeId().isEmpty()) result += '%' + address.scopeId().toLower();
    if (address.protocol() == QAbstractSocket::IPv6Protocol && hasPort) result = '[' + result + ']';
    if (hasPort) result += ':' + QString::number(port);
    return result;
}

std::optional<QString> ProtocolSecurityPolicy::canonicalEndpoint(const QHostAddress& address, quint16 port) {
    if (address.isNull() || port == 0) return {};
    QHostAddress normalized = address;
    const QString rendered = address.toString();
    if (address.protocol() == QAbstractSocket::IPv6Protocol && rendered.startsWith(QStringLiteral("::ffff:"), Qt::CaseInsensitive))
        normalized = QHostAddress(address.toIPv4Address());
    const QString host = normalized.protocol() == QAbstractSocket::IPv6Protocol
        ? QStringLiteral("[") + normalized.toString() + QStringLiteral("]")
        : normalized.toString();
    return canonicalEndpoint(host + QStringLiteral(":") + QString::number(port));
}

std::optional<QByteArray> ProtocolSecurityPolicy::issue(const QUuid& peer, const QUuid& authenticatedPeer, const QString& endpoint, const QSet<QString>& caps, const QByteArray& key, qint64 lifetime) const {
    const auto canonicalEndpointValue = canonicalEndpoint(endpoint);
    if (!clock_ || peer.isNull() || authenticatedPeer.isNull() || peer != authenticatedPeer || !canonicalEndpointValue || key.size()!=32 || lifetime<=0 || lifetime>300000 || caps.isEmpty()) return {};
    const qint64 issued=clock_(), expires=issued+lifetime; QByteArray nonce(16, Qt::Uninitialized); QRandomGenerator::global()->generate(nonce.begin(), nonce.end());
    const QByteArray body=canonical(peer,*canonicalEndpointValue,caps,issued,expires,nonce), tag=mac(key,body); if(tag.size()!=32)return{};
    return QByteArray("v1.")+QByteArray::number(issued)+'.'+QByteArray::number(expires)+'.'+nonce.toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals)+'.'+tag.toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals);
}
bool ProtocolSecurityPolicy::accept(const QByteArray& token,const QUuid& peer,const QUuid& authenticatedPeer,const QString& endpoint,const QSet<QString>& required,const QByteArray& key) {
    const auto canonicalEndpointValue = canonicalEndpoint(endpoint);
    if(!clock_||peer.isNull()||authenticatedPeer.isNull()||peer != authenticatedPeer||!canonicalEndpointValue||key.size()!=32)return false; const auto parts=token.split('.'); if(parts.size()!=5||parts[0]!="v1")return false;
    bool ok1=false,ok2=false; const qint64 issued=parts[1].toLongLong(&ok1),expires=parts[2].toLongLong(&ok2); const QByteArray nonce=QByteArray::fromBase64(parts[3],QByteArray::Base64UrlEncoding); const QByteArray supplied=QByteArray::fromBase64(parts[4],QByteArray::Base64UrlEncoding); const qint64 now=clock_();
    if(!ok1||!ok2||nonce.size()!=16||supplied.size()!=32||issued>now||expires<=now||expires-issued<=0||expires-issued>300000||required.isEmpty())return false;
    const QByteArray body=canonical(peer,*canonicalEndpointValue,required,issued,expires,nonce); if(mac(key,body)!=supplied)return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if(consumed_.contains(nonce))return false;
    consumed_.insert(nonce);
    if (consumed_.size() > 4096) consumed_.erase(consumed_.begin());
    return true;
}
