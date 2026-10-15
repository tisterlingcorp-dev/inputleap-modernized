#pragma once

#include "ZeroconfMetadata.h"

#include <QHostAddress>
#include <QList>
#include <QString>
#include <QVector>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#endif

// Owned, callback-independent copy of the fields used from DNS_SERVICE_INSTANCE.
// DNSAPI owns the original instance and nested pointers only for the duration
// of its completion callback; callers must copy before returning.
struct WindowsDnsSdInstance {
    QString instanceName;
    QString hostName;
    quint32 interfaceIndex = 0;
    quint16 port = 0;
    QVector<quint32> ipv4Addresses; // DNSAPI IP4_ADDRESS is a network-order DWORD.
    QVector<QByteArray> ipv6Addresses; // Every entry must be exactly 16 bytes.
    QList<QPair<QString, QString>> properties;
};

struct WindowsDnsSdConversion {
    ZeroconfParseResult metadata;
    QList<QHostAddress> addresses;
    QString detail;

    bool ok() const { return metadata.status == ZeroconfParseStatus::Compatible && !addresses.isEmpty(); }
};

struct WindowsDnsSdBrowseEvent {
    QString instanceName;
    QString serviceType;
    QString domain;
    quint32 interfaceIndex = 0;
    bool added = false;
    bool valid = false;
};

class WindowsDnsSdInstanceCodec {
public:
    static WindowsDnsSdConversion convert(const WindowsDnsSdInstance& instance);
#ifdef Q_OS_WIN
    // DNSAPI owns pInstance and all pointed-to data. Copy it while the
    // completion callback is active; the returned value has no borrowed data.
    static WindowsDnsSdInstance copyFromDnsApi(const DNS_SERVICE_INSTANCE& instance);
#endif
    static WindowsDnsSdBrowseEvent decodeResolvedServiceName(const QString& fullyQualifiedName,
                                                              quint32 interfaceIndex);
};

class WindowsDnsSdBrowseRecordCodec {
public:
    static WindowsDnsSdBrowseEvent decodePtr(const QString& ownerName, const QString& targetName,
                                              quint32 interfaceIndex, bool added);
};
