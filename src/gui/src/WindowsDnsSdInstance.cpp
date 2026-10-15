#include "WindowsDnsSdInstance.h"

#include <QSet>
#include <QStringList>
#include <QtEndian>
#include <algorithm>
#include <numeric>

namespace {
QStringList dnsLabels(const QString& name)
{
    QString normalized = name;
    while (normalized.endsWith(QLatin1Char('.'))) normalized.chop(1);
    if (normalized.isEmpty()) return {};
    const auto labels = normalized.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    for (const auto& label : labels) if (label.isEmpty()) return {};
    return labels;
}
}

WindowsDnsSdConversion WindowsDnsSdInstanceCodec::convert(const WindowsDnsSdInstance& instance)
{
    WindowsDnsSdConversion result;
    if (instance.port == 0) {
        result.detail = QStringLiteral("DNS-SD instance has an invalid zero port");
        return result;
    }

    QList<QByteArray> wireEntries;
    QSet<QString> keys;
    qsizetype wireSize = 0;
    for (const auto& property : instance.properties) {
        const QString& key = property.first;
        const QString& value = property.second;
        if (key.isEmpty() || key.contains(QLatin1Char('=')) || key.contains(QChar::Null) ||
            value.contains(QChar::Null) || keys.contains(key.toCaseFolded())) {
            result.detail = QStringLiteral("DNS-SD instance contains an invalid or duplicate TXT property");
            return result;
        }
        keys.insert(key.toCaseFolded());
        const QByteArray entry = key.toUtf8() + '=' + value.toUtf8();
        if (entry.size() > 255 || wireSize + entry.size() + 1 > ZeroconfMetadataCodec::maximumTxtBytes()) {
            result.detail = QStringLiteral("DNS-SD TXT properties exceed protocol limits");
            return result;
        }
        wireSize += entry.size() + 1;
        wireEntries.append(entry);
    }

    QByteArray wireTxt;
    wireTxt.reserve(wireSize);
    for (const auto& entry : wireEntries) {
        wireTxt.append(char(entry.size()));
        wireTxt.append(entry);
    }
    result.metadata = DnsSdTxtRecordCodec::decode(wireTxt);
    if (result.metadata.status != ZeroconfParseStatus::Compatible) {
        result.detail = result.metadata.detail;
        return result;
    }

    QSet<QString> uniqueAddresses;
    for (quint32 address : instance.ipv4Addresses) {
        const QHostAddress parsed(qFromBigEndian(address));
        if (!parsed.isNull() && !uniqueAddresses.contains(parsed.toString())) {
            uniqueAddresses.insert(parsed.toString());
            result.addresses.append(parsed);
        }
    }
    for (const QByteArray& address : instance.ipv6Addresses) {
        if (address.size() != 16) {
            result.addresses.clear();
            result.detail = QStringLiteral("DNS-SD instance contains a malformed IPv6 address");
            return result;
        }
        Q_IPV6ADDR bytes{};
        std::copy(address.cbegin(), address.cend(), bytes.c);
        const QHostAddress parsed(bytes);
        if (!parsed.isNull() && !uniqueAddresses.contains(parsed.toString())) {
            uniqueAddresses.insert(parsed.toString());
            result.addresses.append(parsed);
        }
    }
    if (result.addresses.isEmpty())
        result.detail = QStringLiteral("DNS-SD instance resolved without usable addresses");
    return result;
}

#ifdef Q_OS_WIN
WindowsDnsSdInstance WindowsDnsSdInstanceCodec::copyFromDnsApi(const DNS_SERVICE_INSTANCE& source)
{
    WindowsDnsSdInstance result;
    result.instanceName = QString::fromWCharArray(source.pszInstanceName ? source.pszInstanceName : L"");
    result.hostName = QString::fromWCharArray(source.pszHostName ? source.pszHostName : L"");
    result.port = source.wPort;
    result.interfaceIndex = source.dwInterfaceIndex;
    // DNS_SERVICE_INSTANCE exposes pointers but no array lengths. Copy one
    // address only; the caller's separate PTR/interface state supplies the
    // remaining endpoints without guessing a terminator or reading past them.
    if (source.ip4Address) result.ipv4Addresses.append(*source.ip4Address);
    if (source.ip6Address)
        result.ipv6Addresses.append(QByteArray(reinterpret_cast<const char*>(source.ip6Address->IP6Byte), 16));

    if (source.dwPropertyCount > 256 || (source.dwPropertyCount && (!source.keys || !source.values)))
        return result; // convert() will reject the empty/invalid metadata below.
    for (DWORD i = 0; i < source.dwPropertyCount; ++i) {
        const QString key = source.keys[i] ? QString::fromWCharArray(source.keys[i]) : QString();
        const QString value = source.values[i] ? QString::fromWCharArray(source.values[i]) : QString();
        result.properties.append({key, value});
    }
    return result;
}
#endif

WindowsDnsSdBrowseEvent WindowsDnsSdInstanceCodec::decodeResolvedServiceName(
    const QString& fullyQualifiedName, quint32 interfaceIndex)
{
    WindowsDnsSdBrowseEvent event;
    event.interfaceIndex = interfaceIndex;
    event.added = true;
    if (!interfaceIndex) return event;
    const QStringList labels = dnsLabels(fullyQualifiedName);
    // DNS_SERVICE_INSTANCE documents names as <instance>.<service>.<transport>.<domain>.
    if (labels.size() < 4 || labels.at(0).isEmpty() || !labels.at(1).startsWith(QLatin1Char('_')) ||
        (labels.at(2).compare(QStringLiteral("_tcp"), Qt::CaseInsensitive) != 0 &&
         labels.at(2).compare(QStringLiteral("_udp"), Qt::CaseInsensitive) != 0)) return event;
    event.instanceName = labels.at(0);
    event.serviceType = labels.at(1) + QLatin1Char('.') + labels.at(2);
    event.domain = labels.mid(3).join(QLatin1Char('.')) + QLatin1Char('.');
    event.valid = true;
    return event;
}

WindowsDnsSdBrowseEvent WindowsDnsSdBrowseRecordCodec::decodePtr(const QString& ownerName,
    const QString& targetName, quint32 interfaceIndex, bool added)
{
    WindowsDnsSdBrowseEvent event;
    event.interfaceIndex = interfaceIndex;
    event.added = added;
    if (!interfaceIndex) return event;

    const QStringList owner = dnsLabels(ownerName);
    const QStringList target = dnsLabels(targetName);
    if (owner.size() < 3 || target.size() != owner.size() + 1) return event;

    // owner = _service._tcp.local; target = instance._service._tcp.local
    if (!owner.at(0).startsWith(QLatin1Char('_')) ||
        (owner.at(1).compare(QStringLiteral("_tcp"), Qt::CaseInsensitive) != 0 &&
         owner.at(1).compare(QStringLiteral("_udp"), Qt::CaseInsensitive) != 0)) return event;
    for (qsizetype i = 0; i < owner.size(); ++i)
        if (target.at(i + 1).compare(owner.at(i), Qt::CaseInsensitive) != 0) return event;
    if (target.first().isEmpty()) return event;

    event.instanceName = target.first();
    event.serviceType = owner.at(0) + QLatin1Char('.') + owner.at(1);
    event.domain = owner.mid(2).join(QLatin1Char('.')) + QLatin1Char('.');
    event.valid = true;
    return event;
}
