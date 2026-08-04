#include "ProtectionPanel.h"
#include <gtest/gtest.h>

TEST(ProtectionPanelState, RequiresAllRealProtectionFacts)
{
    ProtectionFacts f;
    EXPECT_EQ(ProtectionPanel::stateFor(f), ProtectionPanel::State::Unpaired);
    f.pairedUuid = QUuid::createUuid(); f.pairedSessionKey = true;
    EXPECT_EQ(ProtectionPanel::stateFor(f), ProtectionPanel::State::Attention);
    f.tlsActive = true; f.receiverGate = true;
    f.permissions = DevicePermissions::ControlMouseKeyboard | DevicePermissions::ReceiveFiles;
    EXPECT_EQ(ProtectionPanel::stateFor(f), ProtectionPanel::State::Complete);
}
TEST(ProtectionPanelState, NeverCallsPartialProtectionComplete)
{
    ProtectionFacts f{QUuid::createUuid(), true, true, true, DevicePermissions::ControlMouseKeyboard};
    EXPECT_EQ(ProtectionPanel::stateFor(f), ProtectionPanel::State::Attention);
}
TEST(ProtectionPanelState, LabelsArePortugueseAndDoNotLeakSecrets)
{
    EXPECT_EQ(ProtectionPanel::stateLabel(ProtectionPanel::State::Complete), "Proteção completa");
    EXPECT_EQ(ProtectionPanel::stateLabel(ProtectionPanel::State::Attention), "Atenção");
    EXPECT_EQ(ProtectionPanel::stateLabel(ProtectionPanel::State::Unpaired), "Sem pareamento");
    EXPECT_EQ(ProtectionPanel::stateExplanation(ProtectionPanel::State::Complete).contains("PSK"), false);
}

TEST(ProtectionPanelState, DashboardBadgeUsesTheSameRealProtectionFacts)
{
    ProtectionFacts facts;
    EXPECT_EQ(ProtectionPanel::badgeLabel(facts), QStringLiteral("Sem pareamento"));

    facts.pairedUuid = QUuid::createUuid();
    facts.pairedSessionKey = true;
    EXPECT_EQ(ProtectionPanel::badgeLabel(facts), QStringLiteral("Atenção"));

    facts.tlsActive = true;
    facts.receiverGate = true;
    facts.permissions = DevicePermissions::ControlMouseKeyboard | DevicePermissions::ReceiveFiles;
    EXPECT_EQ(ProtectionPanel::badgeLabel(facts), QStringLiteral("Proteção completa"));
}
