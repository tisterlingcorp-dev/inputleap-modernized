#include "../src/ClipboardProtectionPolicy.h"
#include <QDir>
#include <gtest/gtest.h>

TEST(ClipboardProtectionTests, FailsClosedWhenPasswordSignalIsUnavailable)
{
    ClipboardProtectionPolicy policy;
    ClipboardProtectionPolicy::Metadata metadata;
    metadata.hasPasswordSignal = false;
    EXPECT_FALSE(policy.accept(metadata, QStringLiteral("texto")));
    EXPECT_EQ(policy.reason(), ClipboardProtectionPolicy::DecisionReason::UnknownSensitiveSource);
}

TEST(ClipboardProtectionTests, RejectsPlatformReportedPasswordWithoutTextHeuristics)
{
    ClipboardProtectionPolicy policy;
    ClipboardProtectionPolicy::Metadata metadata;
    metadata.hasPasswordSignal = true;
    metadata.isPassword = true;
    EXPECT_FALSE(policy.accept(metadata, QStringLiteral("texto normal")));
    EXPECT_EQ(policy.reason(), ClipboardProtectionPolicy::DecisionReason::PasswordField);
}

TEST(ClipboardProtectionTests, ExcludesResolvedProcessPathExactly)
{
    ClipboardProtectionPolicy policy;
    const QString excludedPath = QDir::cleanPath(QDir::tempPath() + QStringLiteral("/Program Files/Password Manager/app.exe"));
    policy.setExcludedApplications({excludedPath});
    ClipboardProtectionPolicy::Metadata metadata;
    metadata.hasPasswordSignal = true;
    metadata.ownerProcessPath = excludedPath.toUpper();
    EXPECT_FALSE(policy.accept(metadata, QStringLiteral("qualquer")));
    EXPECT_EQ(policy.reason(), ClipboardProtectionPolicy::DecisionReason::ExcludedApplication);
}

TEST(ClipboardProtectionTests, PauseBlocksCaptureAndReportsPortugueseState)
{
    ClipboardProtectionPolicy policy;
    ClipboardProtectionPolicy::Metadata metadata;
    metadata.hasPasswordSignal = true;
    policy.setPaused(true);
    EXPECT_FALSE(policy.accept(metadata, QStringLiteral("texto")));
    EXPECT_EQ(policy.stateLabel(), QStringLiteral("Pausado"));
    policy.setPaused(false);
    EXPECT_EQ(policy.stateLabel(), QStringLiteral("Ativo"));
}
