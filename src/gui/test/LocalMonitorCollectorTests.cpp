/* InputLeap -- mouse and keyboard sharing utility */
#include "LocalMonitorCollector.h"
#include <gtest/gtest.h>
#include <limits>

namespace {
class FakeScreens final : public LocalScreenSource {
public:
    QList<LocalScreenDescription> values;
    QList<LocalScreenDescription> screens() const override { return values; }
};
LocalScreenDescription screen(QString name, QRect geometry, QString serial = {}, QString maker = {}, QString model = {}, qreal dpr = 1.0)
{
    return {std::move(name), std::move(serial), std::move(maker), std::move(model), geometry, dpr, Qt::PrimaryOrientation};
}
}

TEST(LocalMonitorCollectorTests, NormalizesNegativeCoordinatesAndPreservesMixedDpr)
{
    FakeScreens source; source.values = {screen("Left", {-1920, 0, 1920, 1080}, "A", "Acme", "X", 1.0), screen("Right", {0, -200, 2560, 1440}, "B", "Acme", "Y", 1.5)};
    const auto result = LocalMonitorCollector::collect(source);
    ASSERT_TRUE(result.ok); ASSERT_EQ(result.monitors.size(), 2u);
    EXPECT_EQ(result.desktopSize, QSize(4480, 1440));
    EXPECT_EQ(result.monitors[0].geometry, QRect(0, 200, 1920, 1080));
    EXPECT_EQ(result.monitors[1].geometry, QRect(1920, 0, 2560, 1440));
    EXPECT_DOUBLE_EQ(result.monitors[1].devicePixelRatio, 1.5);
}

TEST(LocalMonitorCollectorTests, HardwareIdentitySurvivesReorderResolutionAndPositionChanges)
{
    FakeScreens first; first.values = {screen("One", {0,0,100,100}, "SER1", "Maker", "Model"), screen("Two", {100,0,100,100}, "SER2", "Maker", "Model")};
    FakeScreens second; second.values = {screen("Renamed B", {-300,0,300,200}, "SER2", "Maker", "Model"), screen("Renamed A", {0,0,200,100}, "SER1", "Maker", "Model")};
    const auto a=LocalMonitorCollector::collect(first), b=LocalMonitorCollector::collect(second);
    EXPECT_EQ(a.monitors[0].id, b.monitors[1].id);
    EXPECT_EQ(a.monitors[1].id, b.monitors[0].id);
    EXPECT_TRUE(a.monitors[0].stableIdentity);
}

TEST(LocalMonitorCollectorTests, MissingAndDuplicateIdentifiersAreUniqueDeterministicButMarkedUnstable)
{
    FakeScreens source; source.values = {screen("Display", {100,0,100,100}), screen("Display", {0,0,100,100}), screen("Same", {200,0,100,100}, "X", "M", "Z"), screen("Same", {300,0,100,100}, "X", "M", "Z")};
    const auto a=LocalMonitorCollector::collect(source), b=LocalMonitorCollector::collect(source);
    ASSERT_EQ(a.monitors.size(),4u);
    for (size_t i=0;i<a.monitors.size();++i) { EXPECT_EQ(a.monitors[i].id,b.monitors[i].id); EXPECT_FALSE(a.monitors[i].stableIdentity); }
    QSet<QString> ids; for(const auto& monitor:a.monitors) ids.insert(monitor.id); EXPECT_EQ(ids.size(),4);
}

TEST(LocalMonitorCollectorTests, RejectsMoreThanSixteenInsteadOfSilentlyTruncating)
{
    FakeScreens source; for(int i=0;i<17;++i) source.values.push_back(screen(QString("D%1").arg(i), {i*10,0,10,10}, QString::number(i)));
    const auto result=LocalMonitorCollector::collect(source);
    EXPECT_FALSE(result.ok); EXPECT_TRUE(result.monitors.empty());
}

TEST(LocalMonitorCollectorTests, RejectsNonFiniteOrExtremeScale)
{
    FakeScreens source;source.values={screen("bad",{0,0,100,100},{},{},{},std::numeric_limits<qreal>::quiet_NaN())};
    EXPECT_FALSE(LocalMonitorCollector::collect(source).ok);
    source.values={screen("bad",{0,0,100,100},{},{},{},32.0)};
    EXPECT_FALSE(LocalMonitorCollector::collect(source).ok);
}
