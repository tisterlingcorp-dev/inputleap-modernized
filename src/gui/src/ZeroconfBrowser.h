/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2014-2016 Symless Ltd.
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "ZeroconfRecord.h"
#include "ZeroconfMetadata.h"
#include "ZeroconfDiscoveryCoordinator.h"

#include <QtCore/QObject>
#define _MSL_STDINT_H
#include <stdint.h>
#include <dns_sd.h>

#include <memory>
#include <vector>

class QSocketNotifier;

class ZeroconfBrowser : public QObject
{
    Q_OBJECT

public:
    ZeroconfBrowser(QObject* parent = nullptr);
    ~ZeroconfBrowser();
    void browseForType(const QString& type);
    inline QList<ZeroconfRecord> currentRecords() const { return m_Records; }
    inline QString serviceType() const { return m_BrowsingType; }
    ZeroconfDiscoveryEvent observeAdvertisement(const ZeroconfMetadata&, const QString& address, quint32 interfaceIndex);
    void removeAdvertisement(const QUuid& uuid, quint32 interfaceIndex);
    void removeAdvertisementAddress(const QUuid& uuid, const QString& address, quint32 interfaceIndex);
    void expireAdvertisements();

Q_SIGNALS:
    void currentRecordsChanged(const QList<ZeroconfRecord>& list);
    void error(DNSServiceErrorType err);
    void advertisementFound(const DiscoveredDeviceAdvertisement& advertisement);
    void advertisementUpdated(const DiscoveredDeviceAdvertisement& advertisement);
    void advertisementLost(const DiscoveredDeviceAdvertisement& advertisement);
    void legacyAdvertisement(const QString& serviceName, quint32 interfaceIndex);
    void advertisementDiagnostic(ZeroconfParseStatus status, const QString& detail);

private slots:
    void socketReadyRead();

private:
    static void DNSSD_API browseReply(DNSServiceRef, DNSServiceFlags flags,
            quint32, DNSServiceErrorType errorCode, const char* serviceName,
            const char* regType, const char* replyDomain, void* context);
    static void DNSSD_API resolveReply(DNSServiceRef, DNSServiceFlags, quint32, DNSServiceErrorType,
        const char*, const char*, quint16, quint16, const unsigned char*, void*);
    static void DNSSD_API addressReply(DNSServiceRef, DNSServiceFlags, quint32, DNSServiceErrorType,
        const char*, const struct sockaddr*, quint32, void*);
    struct Operation;
    void startResolve(const QString&, const QString&, const QString&, quint32);
    void processOperation(Operation*);
    void removeOperation(Operation*);
    void cancelOperation(const QString& key);
    void beginAddressLookup(const QString& key, quint64 token, const QString& host, quint32 interfaceIndex);
    static QString instanceKey(const QString&, const QString&, const QString&, quint32);

private:
    DNSServiceRef m_DnsServiceRef;
    std::unique_ptr<QSocketNotifier> socket_;
    QList<ZeroconfRecord> m_Records;
    QHash<QString, ZeroconfRecord> instanceRecords_;
    QString m_BrowsingType;
    ZeroconfDiscoveryCache discoveryCache_;
    ZeroconfDiscoveryCoordinator coordinator_;
    std::vector<std::unique_ptr<Operation>> operations_;
    QHash<QString, QUuid> instanceUuids_;
    class QTimer* expiryTimer_ = nullptr;
};
