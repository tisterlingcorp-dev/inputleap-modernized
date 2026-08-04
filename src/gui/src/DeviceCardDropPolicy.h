#pragma once
#include <QStringList>

class QMimeData;

class DeviceCardDropPolicy {
public:
    enum class Confirmation { None, Dangerous, Directory };
    struct Result {
        bool accepted = false;
        QStringList paths;
        Confirmation confirmation = Confirmation::None;
        QString reason;
    };
    static constexpr int MaximumItems = 100;
    static Result evaluate(const QMimeData* mimeData);
};
