/* InputLeap -- mouse and keyboard sharing utility */
#pragma once

#include "ScreenSetupModel.h"
#include <QList>

struct LocalScreenDescription {
    QString name;
    QString serialNumber;
    QString manufacturer;
    QString model;
    QRect geometry;
    qreal devicePixelRatio = 1.0;
    Qt::ScreenOrientation orientation = Qt::PrimaryOrientation;
};

class LocalScreenSource {
public:
    virtual ~LocalScreenSource() = default;
    virtual QList<LocalScreenDescription> screens() const = 0;
};

class QtLocalScreenSource final : public LocalScreenSource {
public:
    QList<LocalScreenDescription> screens() const override;
};

class LocalMonitorCollector {
public:
    struct Result {
        bool ok = false;
        QSize desktopSize;
        std::vector<ScreenLayout::Monitor> monitors;
        QString error;
    };
    static Result collect(const LocalScreenSource& source);
};