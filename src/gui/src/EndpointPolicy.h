#pragma once
#include <QString>
#include <QStringList>
class EndpointPolicy { public: static bool isUsableUnicast(const QString&); static bool isNumeric(const QString&); static QString normalizedHost(const QString&); static QString firstUsable(const QStringList&); };
