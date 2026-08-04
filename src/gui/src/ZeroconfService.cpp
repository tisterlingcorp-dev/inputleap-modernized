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

#include "ZeroconfService.h"

#include "MainWindow.h"
#include "ZeroconfRegister.h"
#include "ZeroconfBrowser.h"
#include "ZeroconfMetadata.h"
#include "LocalDeviceIdentity.h"
#include "common/Version.h"

#include <QtNetwork>
#include <QSettings>
#include <QTimer>
#define _MSL_STDINT_H
#include <stdint.h>
#include <dns_sd.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <stdlib.h>
#endif

static const QStringList preferedIPAddress(
                QStringList() <<
                "192.168." <<
                "10." <<
                "172.");

const char* ZeroconfService:: m_ServerServiceName = "_inputLeapServerZeroconf._tcp";
const char* ZeroconfService:: m_ClientServiceName = "_inputLeapClientZeroconf._tcp";

static void silence_avahi_warning()
{
    // the libavahi folks seemingly find Apple's bonjour API distasteful
    // and are quite liberal in taking it out on users...unless we set
    // this environmental variable before calling the avahi library.
    // additionally, Microsoft does not give us a POSIX setenv() so
    // we use their OS-specific API instead
    const char *name  = "AVAHI_COMPAT_NOWARN";
    const char *value = "1";
#ifdef _WIN32
#if QT_VERSION_MAJOR < 6
    SetEnvironmentVariable(name, value);
#else
    SetEnvironmentVariable(reinterpret_cast<LPCWSTR>(name), reinterpret_cast<LPCWSTR>(value));
#endif
#else
    setenv(name, value, 1);
#endif
}

ZeroconfService::ZeroconfService(MainWindow* mainWindow) :
    m_pMainWindow(mainWindow),
    m_ServiceRegistered(false)
{
    silence_avahi_warning();
    const bool server = m_pMainWindow->app_role() == AppRole::Server;
    m_ServerRole = server;
    m_RetryTimer = new QTimer(this);
    m_RetryTimer->setSingleShot(true);
    connect(m_RetryTimer, &QTimer::timeout, this, [this] {
        m_RetryPolicy.retryStarted();
        if (!registerService(m_ServerRole)) {
            scheduleRegistrationRetry();
        }
    });
    zeroconf_browser_ = std::make_unique<ZeroconfBrowser>(this);
    connect(zeroconf_browser_.get(), &ZeroconfBrowser::error,
            this, &ZeroconfService::errorHandle);
    connect(zeroconf_browser_.get(), &ZeroconfBrowser::advertisementFound,
            this, &ZeroconfService::advertisementFound);
    connect(zeroconf_browser_.get(), &ZeroconfBrowser::advertisementUpdated,
            this, &ZeroconfService::advertisementUpdated);
    connect(zeroconf_browser_.get(), &ZeroconfBrowser::advertisementLost,
            this, &ZeroconfService::advertisementLost);
    if (server) connect(zeroconf_browser_.get(), &ZeroconfBrowser::currentRecordsChanged, this, &ZeroconfService::clientDetected);
    else connect(zeroconf_browser_.get(), &ZeroconfBrowser::currentRecordsChanged, this, &ZeroconfService::serverDetected);
    zeroconf_browser_->browseForType(QLatin1String(server ? m_ClientServiceName : m_ServerServiceName));
    if (!registerService(server)) {
        scheduleRegistrationRetry();
    }

}

ZeroconfService::~ZeroconfService() = default;

void ZeroconfService::serverDetected(const QList<ZeroconfRecord>& list)
{
    for (const ZeroconfRecord& record : list) {
        m_pMainWindow->appendLogInfo(tr("zeroconf server detected: %1").arg(record.serviceName));
        m_pMainWindow->serverDetected(record.serviceName);
    }
}

void ZeroconfService::clientDetected(const QList<ZeroconfRecord>& list)
{
    for (const ZeroconfRecord& record : list) {
        m_pMainWindow->appendLogInfo(tr("zeroconf client detected: %1").arg(record.serviceName));
        m_pMainWindow->autoAddScreen(record.serviceName);
    }
}

void ZeroconfService::errorHandle(DNSServiceErrorType errorCode)
{
    m_pMainWindow->appendLogError(
        tr("Falha temporária no serviço de descoberta (código %1)").arg(errorCode));
}

void ZeroconfService::scheduleRegistrationRetry()
{
    if (m_ServiceRegistered || m_RetryTimer == nullptr) {
        return;
    }
    const auto delay = m_RetryPolicy.fail();
    if (delay.has_value()) {
        m_RetryTimer->start(*delay);
        m_pMainWindow->appendLogInfo(
            tr("Nova tentativa de descoberta em %1 segundos").arg(*delay / 1000));
    }
}

bool ZeroconfService::registerService(bool server)
{
    bool result = true;

    if (!m_ServiceRegistered) {
        if (!m_zeroconfServer.isListening() && !m_zeroconfServer.listen()) {
            m_pMainWindow->appendLogError(
                tr("Não foi possível iniciar a descoberta: %1")
                    .arg(m_zeroconfServer.errorString()));
            result = false;
        }
        else {
            zeroconf_register_ = std::make_unique<ZeroconfRegister>(this);
            connect(zeroconf_register_.get(), &ZeroconfRegister::error, this, [this](DNSServiceErrorType code) {
                m_ServiceRegistered = false;
                errorHandle(code);
                scheduleRegistrationRetry();
            });
            connect(zeroconf_register_.get(), &ZeroconfRegister::serviceRegistered, this,
                    [this](const ZeroconfRecord&) {
                        m_ServiceRegistered = true;
                        m_RetryPolicy.confirm();
                        if (m_RetryTimer != nullptr) m_RetryTimer->stop();
                    });
            QSettings settings;
            const auto identity = LocalDeviceIdentity::loadOrCreate(settings);
            if (!identity.ok) {
                m_pMainWindow->appendLogError(identity.detail);
                return false;
            }
            ZeroconfMetadata metadata;
            metadata.uuid = identity.uuid;
            metadata.technicalName = m_pMainWindow->getScreenName();
            metadata.friendlyName = metadata.technicalName;
#if defined(Q_OS_WIN)
            metadata.osFamily = ZeroconfOsFamily::Windows;
#elif defined(Q_OS_MACOS)
            metadata.osFamily = ZeroconfOsFamily::MacOS;
#elif defined(Q_OS_LINUX)
            metadata.osFamily = ZeroconfOsFamily::Linux;
#else
            metadata.osFamily = ZeroconfOsFamily::Other;
#endif
            metadata.inputLeapVersion = QStringLiteral(INPUTLEAP_VERSION);
            metadata.role = server ? ZeroconfRole::Server : ZeroconfRole::Client;
            metadata.capabilities = {ZeroconfCapability::Keyboard, ZeroconfCapability::Mouse,
                                     ZeroconfCapability::Clipboard, ZeroconfCapability::FileTransfer};
            metadata.controlPort = server ? m_pMainWindow->controlPort() : 0;
            metadata.transferPort = 24810;
            metadata.pairingPort = m_pMainWindow->pairingPort();
            metadata.features = {"tls-psk", "file-transfer", "folder-transfer", "pairing-srp6a-v1", "monitor-metadata-v1"};
            CapabilityNegotiationPolicy localCapabilities;
            for (auto it=localCapabilities.localSupport().cbegin();it!=localCapabilities.localSupport().cend();++it)
                metadata.protocolVersions.insert(it.key(),it.value().maximum);
            const auto encoded = ZeroconfMetadataCodec::serialize(metadata);
            if (!encoded.ok) {
                m_pMainWindow->appendLogError(encoded.detail);
                return false;
            }
            if (!zeroconf_register_->registerService(
                ZeroconfRecord(metadata.technicalName,
                    QLatin1String(server ? m_ServerServiceName : m_ClientServiceName), QString()),
                server ? metadata.controlPort : m_zeroconfServer.serverPort(), encoded.txt)) {
                return false;
            }

            // Registration remains pending until the asynchronous callback.
        }
    }

    return result;
}
