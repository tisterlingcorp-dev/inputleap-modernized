/* InputLeap -- mouse and keyboard sharing utility */
#include "LocalMonitorCollector.h"
#include <QCryptographicHash>
#include <QGuiApplication>
#include <QScreen>
#include <algorithm>
#include <tuple>
#include <cmath>

QList<LocalScreenDescription> QtLocalScreenSource::screens() const
{
    QList<LocalScreenDescription> result;
    for (const QScreen* screen : QGuiApplication::screens())
        result.push_back({screen->name(), screen->serialNumber(), screen->manufacturer(), screen->model(),
                          screen->geometry(), screen->devicePixelRatio(), screen->orientation()});
    return result;
}

LocalMonitorCollector::Result LocalMonitorCollector::collect(const LocalScreenSource& source)
{
    Result result;
    QList<LocalScreenDescription> screens = source.screens();
    if (screens.isEmpty()) { result.error = QStringLiteral("Nenhum monitor local foi detectado."); return result; }
    if (screens.size() > ScreenLayout::MaxMonitorsPerDevice) { result.error = QStringLiteral("Mais de 16 monitores locais não são suportados."); return result; }
    QRect desktop;
    for (const auto& screen : screens) {
        if (!screen.geometry.isValid() || !std::isfinite(screen.devicePixelRatio) || screen.devicePixelRatio < 0.25 || screen.devicePixelRatio > 16.0) { result.error = QStringLiteral("A geometria ou escala de um monitor local é inválida."); return result; }
        desktop = desktop.united(screen.geometry);
    }
    struct Pending { LocalScreenDescription screen; QString baseId; bool hardwareStable; };
    std::vector<Pending> pending; pending.reserve(screens.size());
    QHash<QString,int> counts;
    for (const auto& screen : screens) {
        const bool hardware = !screen.serialNumber.trimmed().isEmpty();
        const QString identity = hardware
            ? QStringLiteral("%1\x1f%2\x1f%3").arg(screen.serialNumber.trimmed(), screen.manufacturer.trimmed(), screen.model.trimmed())
            : QStringLiteral("fallback\x1f%1\x1f%2,%3,%4,%5").arg(screen.name.trimmed()).arg(screen.geometry.x()).arg(screen.geometry.y()).arg(screen.geometry.width()).arg(screen.geometry.height());
        const QString base = QStringLiteral("monitor-") + QString::fromLatin1(QCryptographicHash::hash(identity.toUtf8(), QCryptographicHash::Sha256).toHex().left(24));
        pending.push_back({screen,base,hardware}); ++counts[base];
    }
    for (const auto& item : pending) {
        const bool uniqueHardware = item.hardwareStable && counts[item.baseId] == 1;
        QString id=item.baseId;
        if (counts[item.baseId] > 1) {
            int rank=1;
            for(const auto& other:pending) if(other.baseId==item.baseId &&
                std::make_tuple(other.screen.geometry.x(),other.screen.geometry.y(),other.screen.geometry.width(),other.screen.geometry.height(),other.screen.name) <
                std::make_tuple(item.screen.geometry.x(),item.screen.geometry.y(),item.screen.geometry.width(),item.screen.geometry.height(),item.screen.name)) ++rank;
            id += QStringLiteral("-%1").arg(rank);
        }
        result.monitors.push_back({id,item.screen.geometry.translated(-desktop.topLeft()),item.screen.devicePixelRatio,item.screen.orientation,uniqueHardware});
    }
    result.desktopSize=desktop.size(); result.ok=true; return result;
}