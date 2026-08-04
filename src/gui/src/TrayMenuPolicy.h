#pragma once

#include "DiscoveredDevicesModel.h"
#include <optional>

class TrayMenuPolicy
{
public:
    static constexpr int MaximumPeers = 4;

    struct Target {
        QUuid uuid;
        QString address;
        quint16 transferPort = 0;
    };

    struct PeerEntry {
        QString displayName;
        Target target;
        bool sendEnabled = false;
    };

    struct Menu {
        QString openText = QStringLiteral("&Abrir InputLeap");
        QString peersText = QStringLiteral("Computadores ativos");
        QString sendText = QStringLiteral("Enviar &arquivo…");
        QString transfersText = QStringLiteral("&Transferências");
        QString quitText = QStringLiteral("&Sair");
        QList<PeerEntry> peers;
        bool showPause = false;
    };

    struct Visibility {
        bool mainWindowVisible = false;
        bool trayIconVisible = true;
    };

    static Menu build(const QList<DiscoveredDeviceView>& devices);
    static Visibility visibility(bool mainWindowVisible);
    static std::optional<DiscoveredDeviceView> resolveTarget(
        const Target& captured, const DiscoveredDeviceView& current);

private:
    static bool active(DeviceConnectionModel::State state);
    static QString usableAddress(const QSet<QString>& addresses);
    static bool transferable(const DiscoveredDeviceView& device, const QString& address);
};
