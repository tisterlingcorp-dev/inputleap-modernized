#include "AboutDialog.h"

#include <gtest/gtest.h>
#include <QLabel>
#include <QPushButton>

TEST(AboutDialogAccessibility, RemainsResizableForLongTranslations)
{
    AboutDialog dialog(nullptr, QStringLiteral("InputLeap"));
    EXPECT_FALSE(dialog.minimumSize().isEmpty());
    EXPECT_LT(dialog.minimumWidth(), dialog.maximumWidth());
    EXPECT_LT(dialog.minimumHeight(), dialog.maximumHeight());

    const auto buttons = dialog.findChildren<QPushButton*>();
    ASSERT_FALSE(buttons.isEmpty());
    for (const auto* button : buttons)
        EXPECT_FALSE(button->accessibleName().isEmpty());
}

TEST(AboutDialogAccessibility, ShowsTheCompiledApplicationVersion)
{
    AboutDialog dialog(nullptr, QStringLiteral("InputLeap"));
    const auto* version = dialog.findChild<QLabel*>(QStringLiteral("m_pLabelAppVersion"));
    ASSERT_NE(version, nullptr);
    EXPECT_EQ(version->text(), QStringLiteral(INPUTLEAP_VERSION));
}
