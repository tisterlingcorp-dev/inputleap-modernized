#include "../src/ClipboardHistoryDialog.h"
#include "../src/ClipboardHistoryModel.h"

#include <gtest/gtest.h>
#include <QApplication>
#include <QClipboard>
#include <QImage>
#include <QMimeData>
#include <QPushButton>
#include <QLabel>

namespace {
ClipboardHistoryModel::Limits smallLimits()
{
    ClipboardHistoryModel::Limits limits;
    limits.maxItems = 2;
    limits.maxItemBytes = 32;
    limits.maxTotalBytes = 40;
    limits.expiryMs = 100;
    limits.maxImageWidth = 8;
    limits.maxImageHeight = 8;
    limits.maxImagePixels = 64;
    return limits;
}
}

TEST(ClipboardHistoryTests, StartsDisabledAndDoesNotCaptureWithoutConsent)
{
    qint64 now = 1'710'000'000'000;
    ClipboardHistoryModel model([&now] { return now; });

    EXPECT_FALSE(model.isEnabled());
    EXPECT_FALSE(model.addText(QStringLiteral("segredo")));
    EXPECT_EQ(model.rowCount(), 0);
}

TEST(ClipboardHistoryTests, CapturesUnicodeTextExactlyAndDeduplicatesConsecutiveContent)
{
    qint64 now = 1000;
    ClipboardHistoryModel model([&now] { return now; });
    model.setEnabled(true);
    const QString text = QString::fromUtf8("Olá 🌎\n\t") + QChar(1);
    ASSERT_TRUE(model.addText(text));
    ASSERT_EQ(model.rowCount(), 1);
    EXPECT_EQ(model.entry(0)->text, text);
    EXPECT_EQ(model.entry(0)->capturedAtMs, 1000);

    now = 1100;
    EXPECT_TRUE(model.addText(text));
    EXPECT_EQ(model.rowCount(), 1);
    EXPECT_EQ(model.entry(0)->capturedAtMs, 1100);
    EXPECT_FALSE(model.addText(QString()));
}

TEST(ClipboardHistoryTests, DeterministicLimitsExpireUnpinnedAndFailClosedAroundPinnedItems)
{
    qint64 now = 0;
    ClipboardHistoryModel model([&now] { return now; }, smallLimits());
    model.setEnabled(true);
    ASSERT_TRUE(model.addText(QStringLiteral("primeiro")));
    ASSERT_TRUE(model.setPinned(0, true));
    now = 50;
    ASSERT_TRUE(model.addText(QStringLiteral("segundo")));
    now = 151;
    model.expire();
    ASSERT_EQ(model.rowCount(), 1);
    EXPECT_EQ(model.entry(0)->text, QStringLiteral("primeiro"));

    EXPECT_TRUE(model.addText(QString(24, QLatin1Char('a'))));
    ASSERT_TRUE(model.setPinned(0, true));
    EXPECT_FALSE(model.addText(QString(33, QLatin1Char('b'))));
    EXPECT_FALSE(model.addText(QString(24, QLatin1Char('c'))));
    EXPECT_EQ(model.rowCount(), 2);
}

TEST(ClipboardHistoryTests, ImageAndMimeCaptureRejectsUnsafeOrUnsupportedInputBeforeEncoding)
{
    auto limits = smallLimits();
    limits.maxItemBytes = 1024;
    limits.maxTotalBytes = 2048;
    ClipboardHistoryModel model([] { return 1; }, limits);
    model.setEnabled(true);
    QImage allowed(2, 2, QImage::Format_ARGB32);
    allowed.fill(Qt::red);
    EXPECT_TRUE(model.addImage(allowed));
    ASSERT_EQ(model.rowCount(), 1);
    EXPECT_EQ(model.entry(0)->type, ClipboardHistoryModel::Type::Image);
    EXPECT_FALSE(model.entry(0)->imagePng.isEmpty());

    QImage tooWide(9, 1, QImage::Format_ARGB32);
    EXPECT_FALSE(model.addImage(tooWide));
    QMimeData urls;
    urls.setUrls({QUrl::fromLocalFile(QStringLiteral("C:/segredo.txt"))});
    urls.setText(QStringLiteral("C:/segredo.txt"));
    EXPECT_FALSE(model.addMimeData(urls));
    QMimeData unknown;
    unknown.setData(QStringLiteral("application/x-private"), QByteArray("x"));
    EXPECT_FALSE(model.addMimeData(unknown));
}

TEST(ClipboardHistoryTests, ClearAndDisableDestroyAllReachablePayloads)
{
    ClipboardHistoryModel model([] { return 1; });
    model.setEnabled(true);
    ASSERT_TRUE(model.addText(QStringLiteral("não persistir")));
    model.clear();
    EXPECT_EQ(model.rowCount(), 0);
    ASSERT_TRUE(model.addText(QStringLiteral("outro segredo")));
    model.setEnabled(false);
    EXPECT_FALSE(model.isEnabled());
    EXPECT_EQ(model.rowCount(), 0);
}

TEST(ClipboardHistoryTests, DialogRequiresConsentShowsHonestStatusAndCopiesLocallyWithoutRecapture)
{
    ClipboardHistoryModel model([] { return 1; });
    ClipboardHistoryDialog dialog(&model, QApplication::clipboard());
    auto* enable = dialog.findChild<QPushButton*>(QStringLiteral("enableHistoryButton"));
    auto* status = dialog.findChild<QLabel*>(QStringLiteral("historyStatusLabel"));
    ASSERT_NE(enable, nullptr);
    ASSERT_NE(status, nullptr);
    EXPECT_TRUE(status->text().contains(QStringLiteral("desativado"), Qt::CaseInsensitive));

    enable->click();
    EXPECT_TRUE(model.isEnabled());
    EXPECT_TRUE(status->text().contains(QStringLiteral("ativo"), Qt::CaseInsensitive));
    ASSERT_TRUE(model.addText(QStringLiteral("texto local")));
    dialog.selectRowForTest(0);
    dialog.copySelectedAgain();
    QCoreApplication::processEvents();
    EXPECT_EQ(QApplication::clipboard()->text(), QStringLiteral("texto local"));
    EXPECT_EQ(model.rowCount(), 1);
    EXPECT_TRUE(dialog.sharingExplanation().contains(QStringLiteral("conexão"), Qt::CaseInsensitive));
    dialog.clearAll();
    EXPECT_EQ(model.rowCount(), 0);
}
