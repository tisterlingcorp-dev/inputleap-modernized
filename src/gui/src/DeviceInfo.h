/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#pragma once

#include <QDateTime>
#include <QString>
#include <QStringList>
#include <QUuid>

class DeviceInfo
{
public:
    enum class TrustState { Unknown, Untrusted, Trusted };

    DeviceInfo() = default;
    explicit DeviceInfo(const QUuid& uuid);

    bool isValid() const;
    const QUuid& uuid() const;
    const QString& technicalName() const;
    const QString& localAlias() const;
    const QString& operatingSystem() const;
    const QStringList& ipAddresses() const;
    const QString& version() const;
    const QStringList& capabilities() const;
    TrustState trustState() const;
    const QDateTime& lastSeen() const;

    void setTechnicalName(const QString& value);
    void setLocalAlias(const QString& value);
    void setOperatingSystem(const QString& value);
    void setIpAddresses(const QStringList& value);
    void setVersion(const QString& value);
    void setCapabilities(const QStringList& value);
    void setTrustState(TrustState value);
    void setLastSeen(const QDateTime& value);

private:
    QUuid uuid_;
    QString technicalName_;
    QString localAlias_;
    QString operatingSystem_;
    QStringList ipAddresses_;
    QString version_;
    QStringList capabilities_;
    TrustState trustState_ = TrustState::Unknown;
    QDateTime lastSeen_;
};
