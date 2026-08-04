#pragma once

#include <QObject>
#include <QHash>
#include <QString>

#include <functional>
#include <limits>

class NotificationService final : public QObject
{
    Q_OBJECT
public:
    enum class Severity { Information, Warning, Error };
    struct Event {
        QString key;
        QString title;
        QString message;
        Severity severity = Severity::Information;
        int suppressedCount = 0;
    };
    using Clock = std::function<qint64()>;

    explicit NotificationService(Clock clock = {}, QObject* parent = nullptr);

    bool publish(const QString& key, const QString& title, const QString& message,
                 Severity severity = Severity::Information,
                 qint64 rateLimitMs = 30000);
    void reset(const QString& key);

Q_SIGNALS:
    void notificationRaised(const NotificationService::Event& event);

private:
    struct State {
        qint64 lastRaisedMs = std::numeric_limits<qint64>::min();
        int suppressedCount = 0;
    };
    Clock clock_;
    QHash<QString, State> states_;
};

Q_DECLARE_METATYPE(NotificationService::Event)
