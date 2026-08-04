#include "NotificationService.h"

#include <gtest/gtest.h>

TEST(NotificationService, RaisesFirstEventAndGroupsRepeatsWithinRateLimit)
{
    qint64 now = 1000;
    NotificationService service([&now] { return now; });
    QList<NotificationService::Event> events;
    QObject::connect(&service, &NotificationService::notificationRaised,
                     [&events](const NotificationService::Event& event) { events.append(event); });

    EXPECT_TRUE(service.publish(QStringLiteral("reconnect"), QStringLiteral("Conexão"),
                                QStringLiteral("Reconexão iniciada."),
                                NotificationService::Severity::Information, 1000));
    EXPECT_FALSE(service.publish(QStringLiteral("reconnect"), QStringLiteral("Conexão"),
                                 QStringLiteral("Reconexão iniciada."),
                                 NotificationService::Severity::Information, 1000));
    now = 1500;
    EXPECT_FALSE(service.publish(QStringLiteral("reconnect"), QStringLiteral("Conexão"),
                                 QStringLiteral("Reconexão iniciada."),
                                 NotificationService::Severity::Information, 1000));
    now = 2000;
    EXPECT_TRUE(service.publish(QStringLiteral("reconnect"), QStringLiteral("Conexão"),
                                QStringLiteral("Reconexão iniciada."),
                                NotificationService::Severity::Information, 1000));
    ASSERT_EQ(events.size(), 2);
    EXPECT_EQ(events.at(1).suppressedCount, 2);
}

TEST(NotificationService, KeepsIndependentEventKeysIndependentAndResetClearsSuppression)
{
    qint64 now = 10;
    NotificationService service([&now] { return now; });
    int raised = 0;
    QObject::connect(&service, &NotificationService::notificationRaised,
                     [&raised](const NotificationService::Event&) { ++raised; });
    EXPECT_TRUE(service.publish(QStringLiteral("pairing"), QStringLiteral("Pareamento"), QStringLiteral("Código"),
                                NotificationService::Severity::Information, 100));
    EXPECT_TRUE(service.publish(QStringLiteral("transfer"), QStringLiteral("Transferência"), QStringLiteral("Iniciada"),
                                NotificationService::Severity::Information, 100));
    EXPECT_FALSE(service.publish(QStringLiteral("pairing"), QStringLiteral("Pareamento"), QStringLiteral("Código"),
                                 NotificationService::Severity::Information, 100));
    service.reset(QStringLiteral("pairing"));
    EXPECT_TRUE(service.publish(QStringLiteral("pairing"), QStringLiteral("Pareamento"), QStringLiteral("Código"),
                                NotificationService::Severity::Information, 100));
    EXPECT_EQ(raised, 3);
}
