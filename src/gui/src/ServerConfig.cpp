/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ServerConfig.h"
#include "ConfigurationTransactionLock.h"
#include "Hotkey.h"
#include "MainWindow.h"
#include "AddClientDialog.h"

#include <QtCore>
#include <QMessageBox>
#include <QAbstractButton>
#include <QPushButton>

#include <type_traits>

static const struct
{
     int x;
     int y;
     const char* name;
} neighbourDirs[] =
{
    {  1,  0, "right" },
    { -1,  0, "left" },
    {  0, -1, "up" },
    {  0,  1, "down" },

};

const int serverDefaultIndex = 7;

namespace {
QString asciiCaselessKey(const QString& value)
{
    QString key = value;
    for (QChar& character : key) {
        const ushort code = character.unicode();
        if (code >= 'A' && code <= 'Z') character = QChar(code + ('a' - 'A'));
    }
    return key;
}

bool hasBoundedUtf8(const QString& value, qsizetype maximumBytes)
{
    return value.size() <= maximumBytes && value.toUtf8().size() <= maximumBytes;
}

bool passesLayoutPreflight(const EnvironmentProfile::Layout& layout)
{
    if (layout.columns < 1 || layout.columns > ServerConfig::MaxColumns ||
        layout.rows < 1 || layout.rows > ServerConfig::MaxRows) return false;
    const qsizetype cellCount = qsizetype(layout.columns) * layout.rows;
    if (cellCount < 1 || cellCount > ServerConfig::MaxGridCells ||
        layout.gridTechnicalNames.size() != cellCount ||
        layout.extension.devices().size() > ScreenLayout::MaxDevices) return false;
    for (const QString& name : layout.gridTechnicalNames)
        if (!name.isEmpty() && !hasBoundedUtf8(name, ScreenLayout::MaxTechnicalNameBytes)) return false;
    for (const auto& device : layout.extension.devices()) {
        if (device.uuid.isNull() ||
            !hasBoundedUtf8(device.technicalName, ScreenLayout::MaxTechnicalNameBytes) ||
            device.monitors.size() > ScreenLayout::MaxMonitorsPerDevice) return false;
        for (const auto& monitor : device.monitors)
            if (!hasBoundedUtf8(monitor.id, ScreenLayout::MaxMonitorIdBytes)) return false;
    }
    return true;
}

bool hasValidCoreNamespace(const std::vector<Screen>& screens)
{
    QSet<QString> canonicalNames;
    for (const Screen& screen : screens) {
        if (screen.isNull()) continue;
        const QString key = asciiCaselessKey(screen.name());
        if (canonicalNames.contains(key)) return false;
        canonicalNames.insert(key);
    }
    QSet<QString> aliases;
    for (const Screen& screen : screens) {
        if (screen.isNull()) continue;
        for (const QString& alias : screen.aliases()) {
            const QString key = asciiCaselessKey(alias);
            if (canonicalNames.contains(key) || aliases.contains(key)) return false;
            aliases.insert(key);
        }
    }
    return true;
}
}

ServerConfig::ServerConfig(QSettings* settings, int numColumns, int numRows ,
                QString serverName, MainWindow* mainWindow) :
    m_pSettings(settings),
    m_Screens(),
    m_NumColumns(numColumns),
    m_NumRows(numRows),
    m_ServerName(serverName),
    m_IgnoreAutoConfigClient(false),
    m_EnableDragAndDrop(false),
    m_ClipboardSharing(true),
    m_ClipboardSharingSize(defaultClipboardSharingSize()),
    m_pMainWindow(mainWindow)
{
    Q_ASSERT(m_pSettings);

    loadSettings();
}

ServerConfig::~ServerConfig()
{
    if (m_PersistenceEnabled)
        saveSettings();
}

EnvironmentProfile::Layout ServerConfig::environmentLayoutSnapshot(
    const QUuid& localUuid) const
{
    EnvironmentProfile::Layout snapshot;
    snapshot.columns = numColumns();
    snapshot.rows = numRows();
    snapshot.gridTechnicalNames.reserve(static_cast<qsizetype>(screens().size()));
    for (const auto& screen : screens()) snapshot.gridTechnicalNames.push_back(screen.name());
    // A snapshot may only rebind names to identities already present in the
    // extension. The sole migration exception is an unambiguous local-only
    // legacy grid whose UUID is absent or is the historical name-derived v5
    // marker; replace that marker with the already persisted local identity.
    qsizetype localIndex = -1;
    int nonEmptyNames = 0;
    for (qsizetype i = 0; i < snapshot.gridTechnicalNames.size(); ++i) {
        if (snapshot.gridTechnicalNames[i].isEmpty()) continue;
        ++nonEmptyNames;
        if (snapshot.gridTechnicalNames[i] == m_ServerName) localIndex = i;
    }
    const bool localOnly = !localUuid.isNull() && nonEmptyNames == 1 && localIndex >= 0;
    const auto& currentDevices = screenLayout().devices();
    const ScreenLayout legacyDerived = ScreenLayout::fromLegacyGrid(
        snapshot.gridTechnicalNames, snapshot.columns, snapshot.rows);
    const bool hasDerivedLegacyMarker = localOnly && currentDevices.size() == 1 &&
        legacyDerived.devices().size() == 1 &&
        currentDevices.front().uuid == legacyDerived.devices().front().uuid;

    if (localOnly && (currentDevices.empty() || hasDerivedLegacyMarker)) {
        ScreenLayout::Device local;
        local.uuid = localUuid;
        local.technicalName = m_ServerName;
        local.geometry = QRect(
            int(localIndex % snapshot.columns) * 100,
            int(localIndex / snapshot.columns) * 100, 100, 100);
        local.monitors.push_back({QStringLiteral("logical-default"),
                                  QRect(0, 0, 100, 100), 1.0,
                                  Qt::PrimaryOrientation, false});
        ScreenLayout migrated({std::move(local)});
        snapshot.extension = migrated.validate().isValid()
            ? std::move(migrated) : ScreenLayout();
    }
    else if (localOnly && currentDevices.size() == 1 &&
             currentDevices.front().uuid != localUuid) {
        // Existing metadata claims that the sole local name belongs to a
        // different stable identity. Preserve fail-closed validation.
        snapshot.extension = ScreenLayout();
    }
    else {
        const auto synchronized = screenLayout().synchronizedToLegacyGridWithExistingIdentity(
            snapshot.gridTechnicalNames, snapshot.columns, snapshot.rows);
        snapshot.extension = synchronized.value_or(screenLayout());
    }
    return snapshot;
}

EnvironmentProfile::Layout ServerConfig::environmentLayoutSnapshot(
    const QUuid& localUuid,
    const QHash<QString, QUuid>& stableIdentities) const
{
    QHash<QString, QUuid> canonicalIdentities;
    for (auto it = stableIdentities.cbegin(); it != stableIdentities.cend(); ++it) {
        const QString key = asciiCaselessKey(it.key());
        if (key.isEmpty())
            continue;
        if (canonicalIdentities.contains(key))
            canonicalIdentities[key] = {};
        else
            canonicalIdentities.insert(key, it.value());
    }
    EnvironmentProfile::Layout snapshot = environmentLayoutSnapshot(localUuid);
    const ScreenLayout legacyDerived = ScreenLayout::fromLegacyGrid(
        snapshot.gridTechnicalNames, snapshot.columns, snapshot.rows);
    std::vector<ScreenLayout::Device> rebound = snapshot.extension.devices();

    for (auto& device : rebound) {
        const auto marker = std::find_if(
            legacyDerived.devices().cbegin(), legacyDerived.devices().cend(),
            [&device](const ScreenLayout::Device& candidate) {
                return candidate.technicalName == device.technicalName;
            });
        if (marker == legacyDerived.devices().cend()) {
            snapshot.extension = ScreenLayout();
            return snapshot;
        }
        const bool nameDerivedMarker = device.uuid == marker->uuid;
        if (device.technicalName == m_ServerName) {
            if (localUuid.isNull() || (!nameDerivedMarker && device.uuid != localUuid)) {
                snapshot.extension = ScreenLayout();
                return snapshot;
            }
            device.uuid = localUuid;
            continue;
        }

        const QString identityKey = asciiCaselessKey(device.technicalName);
        const QUuid registryUuid = canonicalIdentities.value(identityKey);
        if (canonicalIdentities.contains(identityKey) && registryUuid.isNull()) {
            snapshot.extension = ScreenLayout();
            return snapshot;
        }
        if (nameDerivedMarker) {
            if (registryUuid.isNull()) {
                snapshot.extension = ScreenLayout();
                return snapshot;
            }
            device.uuid = registryUuid;
        }
        else if (!registryUuid.isNull() && registryUuid != device.uuid) {
            snapshot.extension = ScreenLayout();
            return snapshot;
        }
    }

    ScreenLayout candidate(std::move(rebound));
    snapshot.extension = candidate.validate().isValid()
        ? std::move(candidate) : ScreenLayout();
    return snapshot;
}

bool ServerConfig::applyEnvironmentLayout(const EnvironmentProfile::Layout& layout)
{
    // Reject structural/resource abuse before copying attacker-controlled data.
    if (!passesLayoutPreflight(layout)) return false;

    EnvironmentProfile candidate;
    candidate.layout = layout;
    for (const auto& extensionDevice : layout.extension.devices()) {
        candidate.devices.push_back({extensionDevice.uuid, extensionDevice.technicalName,
                                     DevicePermissions::None});
    }
    if (!candidate.isValid()) return false;

    LayoutState next{layout.columns, layout.rows, {}, layout.extension};
    next.screens.reserve(static_cast<size_t>(layout.gridTechnicalNames.size()));
    for (const auto& technicalName : layout.gridTechnicalNames) {
        if (technicalName.isEmpty()) {
            next.screens.emplace_back();
            continue;
        }
        const QString requestedKey = asciiCaselessKey(technicalName);
        const auto existing = std::find_if(m_Screens.cbegin(), m_Screens.cend(),
            [&](const Screen& screen) {
                return !screen.isNull() && asciiCaselessKey(screen.name()) == requestedKey;
            });
        if (existing == m_Screens.cend()) {
            next.screens.emplace_back(technicalName);
        }
        else {
            next.screens.push_back(*existing);
            next.screens.back().setName(technicalName);
        }
    }
    if (!hasValidCoreNamespace(next.screens)) return false;

    static_assert(std::is_nothrow_swappable_v<std::vector<Screen>>);
    static_assert(std::is_nothrow_swappable_v<ScreenLayout>);
    using std::swap;
    swap(m_NumColumns, next.columns);
    swap(m_NumRows, next.rows);
    swap(m_Screens, next.screens);
    m_ScreenLayout.swap(next.extension);
    return true;
}

bool ServerConfig::save(const QString& fileName) const
{
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        return false;

    save(file);
    file.close();

    return true;
}

void ServerConfig::save(QFile& file) const
{
    QTextStream outStream(&file);
    outStream << *this;
}

void ServerConfig::init()
{
    switchCorners().clear();
    screens().clear();

    // m_NumSwitchCorners is used as a fixed size array. See Screen::init()
    for (int i = 0; i < static_cast<int>(SwitchCorner::Count); i++) {
        switchCorners() << false;
    }

    // There must always be screen objects for each cell in the screens QList. Unused screens
    // are identified by having an empty name.
    for (int i = 0; i < numColumns() * numRows(); i++)
        addScreen(Screen());
}

void ServerConfig::saveSettings()
{
    if (!m_PersistenceEnabled) return;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return;
    settings().beginGroup("internalConfig");
    settings().remove("");

    settings().setValue("numColumns", numColumns());
    settings().setValue("numRows", numRows());

    settings().setValue("hasHeartbeat", hasHeartbeat());
    settings().setValue("heartbeat", heartbeat());
    settings().setValue("relativeMouseMoves", relativeMouseMoves());
    settings().setValue("screenSaverSync", screenSaverSync());
    settings().setValue("win32KeepForeground", win32KeepForeground());
    settings().setValue("hasSwitchDelay", hasSwitchDelay());
    settings().setValue("switchDelay", switchDelay());
    settings().setValue("hasSwitchDoubleTap", hasSwitchDoubleTap());
    settings().setValue("switchDoubleTap", switchDoubleTap());
    settings().setValue("switchCornerSize", switchCornerSize());
    settings().setValue("ignoreAutoConfigClient", ignoreAutoConfigClient());
    settings().setValue("enableDragAndDrop", enableDragAndDrop());
    settings().setValue("clipboardSharing", clipboardSharing());
    settings().setValue("clipboardSharingSize", (int)clipboardSharingSize());

    writeSettings<bool>(settings(), switchCorners(), "switchCorner");

    settings().beginWriteArray("screens");
    for (std::size_t i = 0; i < screens().size(); i++)
    {
        settings().setArrayIndex(static_cast<int>(i));
        screens()[i].saveSettings(settings());
    }
    settings().endArray();

    // GUI-only extension metadata.  The generated core configuration below
    // intentionally remains name-based for compatibility with older cores.
    QStringList currentNames;
    currentNames.reserve(static_cast<int>(screens().size()));
    for (const Screen& screen : screens()) currentNames.push_back(screen.name());
    m_ScreenLayout.synchronizedToLegacyGrid(currentNames, numColumns(), numRows()).saveMetadata(settings());

    settings().beginWriteArray("hotkeys");
    for (std::size_t i = 0; i < hotkeys().size(); i++)
    {
        settings().setArrayIndex(static_cast<int>(i));
        hotkeys()[i].saveSettings(settings());
    }
    settings().endArray();

    settings().endGroup();
}

void ServerConfig::loadSettings()
{
    settings().beginGroup("internalConfig");

    setNumColumns(settings().value("numColumns", 5).toInt());
    setNumRows(settings().value("numRows", 3).toInt());

    // we need to know the number of columns and rows before we can set up ourselves
    init();

    haveHeartbeat(settings().value("hasHeartbeat", false).toBool());
    setHeartbeat(settings().value("heartbeat", 5000).toInt());
    setRelativeMouseMoves(settings().value("relativeMouseMoves", false).toBool());
    setScreenSaverSync(settings().value("screenSaverSync", true).toBool());
    setWin32KeepForeground(settings().value("win32KeepForeground", false).toBool());
    haveSwitchDelay(settings().value("hasSwitchDelay", false).toBool());
    setSwitchDelay(settings().value("switchDelay", 250).toInt());
    haveSwitchDoubleTap(settings().value("hasSwitchDoubleTap", false).toBool());
    setSwitchDoubleTap(settings().value("switchDoubleTap", 250).toInt());
    setSwitchCornerSize(settings().value("switchCornerSize").toInt());
    setIgnoreAutoConfigClient(settings().value("ignoreAutoConfigClient").toBool());
    setEnableDragAndDrop(settings().value("enableDragAndDrop", true).toBool());
    setClipboardSharing(settings().value("clipboardSharing", true).toBool());
    setClipboardSharingSize(settings().value("clipboardSharingSize",
        (int) ServerConfig::defaultClipboardSharingSize()).toULongLong());

    readSettings<bool>(settings(), switchCorners(), "switchCorner", false,
                       static_cast<int>(SwitchCorner::Count));

    std::size_t numScreens = settings().beginReadArray("screens");
    Q_ASSERT(numScreens <= screens().size());
    for (std::size_t i = 0; i < numScreens; i++)
    {
        settings().setArrayIndex(static_cast<int>(i));
        screens()[i].loadSettings(settings());
    }
    settings().endArray();

    const auto persistedLayout = ScreenLayout::loadMetadata(settings());
    if (persistedLayout.has_value()) {
        m_ScreenLayout = persistedLayout->repaired();
    }
    else {
        QStringList legacyNames;
        legacyNames.reserve(static_cast<int>(screens().size()));
        for (const Screen& screen : screens()) legacyNames.push_back(screen.name());
        m_ScreenLayout = ScreenLayout::fromLegacyGrid(legacyNames, numColumns(), numRows()).repaired();
    }

    int numHotkeys = settings().beginReadArray("hotkeys");
    for (int i = 0; i < numHotkeys; i++)
    {
        settings().setArrayIndex(i);
        Hotkey h;
        h.loadSettings(settings());
        hotkeys().push_back(h);
    }
    settings().endArray();

    settings().endGroup();
}

int ServerConfig::adjacentScreenIndex(int idx, int deltaColumn, int deltaRow) const
{
    if (screens()[idx].isNull())
        return -1;

    // if we're at the left or right end of the table, don't find results going further left or right
    if ((deltaColumn > 0 && (idx+1) % numColumns() == 0)
            || (deltaColumn < 0 && idx % numColumns() == 0))
        return -1;

    int arrayPos = idx + deltaColumn + deltaRow * numColumns();

    if (arrayPos >= static_cast<int>(screens().size()) || arrayPos < 0)
        return -1;

    return arrayPos;
}

QTextStream& operator<<(QTextStream& outStream, const ServerConfig& config)
{
    outStream << "section: screens\n";

    for (const Screen& s : config.screens()) {
        if (!s.isNull())
            s.writeScreensSection(outStream);
    }

    outStream << "end\n\n";

    outStream << "section: aliases\n";

    for (const Screen& s : config.screens()) {
        if (!s.isNull())
            s.writeAliasesSection(outStream);
    }

    outStream << "end\n\n";

    outStream << "section: links\n";

    for (std::size_t i = 0; i < config.screens().size(); i++)
        if (!config.screens()[i].isNull())
        {
            outStream << "\t" << config.screens()[i].name() << ":\n";

            for (unsigned int j = 0; j < sizeof(neighbourDirs) / sizeof(neighbourDirs[0]); j++)
            {
                int idx = config.adjacentScreenIndex(static_cast<int>(i),
                                                     neighbourDirs[j].x, neighbourDirs[j].y);
                if (idx != -1 && !config.screens()[idx].isNull())
                    outStream << "\t\t" << neighbourDirs[j].name << " = " << config.screens()[idx].name() << "\n";
            }
        }

    outStream << "end\n\n";

    outStream << "section: options\n";

    if (config.hasHeartbeat())
        outStream << "\t" << "heartbeat = " << config.heartbeat() << "\n";

    outStream << "\t" << "relativeMouseMoves = " << (config.relativeMouseMoves() ? "true" : "false") << "\n";
    outStream << "\t" << "screenSaverSync = " << (config.screenSaverSync() ? "true" : "false") << "\n";
    outStream << "\t" << "win32KeepForeground = " << (config.win32KeepForeground() ? "true" : "false") << "\n";
    outStream << "\t" << "clipboardSharing = " << (config.clipboardSharing() ? "true" : "false") << "\n";
    outStream << "\t" << "clipboardSharingSize = " << config.clipboardSharingSize() << "\n";

    if (config.hasSwitchDelay())
        outStream << "\t" << "switchDelay = " << config.switchDelay() << "\n";

    if (config.hasSwitchDoubleTap())
        outStream << "\t" << "switchDoubleTap = " << config.switchDoubleTap() << "\n";

    outStream << "\t" << "switchCorners = none ";
    for (int i = 0; i < config.switchCorners().size(); i++) {
        auto corner = static_cast<Screen::SwitchCorner>(i);
        if (config.switchCorners()[i]) {
            outStream << "+" << config.switchCornerName(corner) << " ";
        }
    }
    outStream << "\n";

    outStream << "\t" << "switchCornerSize = " << config.switchCornerSize() << "\n";

    for (const Hotkey& hotkey : config.hotkeys()) {
        outStream << hotkey;
    }

    outStream << "end\n\n";

    return outStream;
}

int ServerConfig::numScreens() const
{
    int rval = 0;

    for (const Screen& s : screens()) {
        if (!s.isNull())
            rval++;
    }

    return rval;
}

int ServerConfig::autoAddScreen(const QString name)
{
    int serverIndex = -1;
    int targetIndex = -1;
    if (!findScreenName(m_ServerName, serverIndex)) {
        if (!fixNoServer(m_ServerName, serverIndex)) {
            return kAutoAddScreenManualServer;
        }
    }
    if (findScreenName(name, targetIndex)) {
        // already exists.
        return kAutoAddScreenIgnore;
    }

    int result = showAddClientDialog(name);

    if (result == kAddClientIgnore) {
        return kAutoAddScreenIgnore;
    }

    if (result == kAddClientOther) {
        addToFirstEmptyGrid(name);
        return kAutoAddScreenManualClient;
    }

    bool success = false;
    int startIndex = serverIndex;
    int offset = 1;
    int dirIndex = 0;

    if (result == kAddClientLeft) {
        offset = -1;
        dirIndex = 1;
    }
    else if (result == kAddClientUp) {
        offset = -5;
        dirIndex = 2;
    }
    else if (result == kAddClientDown) {
        offset = 5;
        dirIndex = 3;
    }


    int idx = adjacentScreenIndex(startIndex, neighbourDirs[dirIndex].x,
                    neighbourDirs[dirIndex].y);
    while (idx != -1) {
        if (screens()[idx].isNull()) {
            m_Screens[idx].setName(name);
            success = true;
            break;
        }

        startIndex += offset;
        idx = adjacentScreenIndex(startIndex, neighbourDirs[dirIndex].x,
                    neighbourDirs[dirIndex].y);
    }

    if (!success) {
        addToFirstEmptyGrid(name);
        return kAutoAddScreenManualClient;
    }

    saveSettings();
    return kAutoAddScreenOk;
}

bool ServerConfig::findScreenName(const QString& name, int& index)
{
    bool found = false;
    for (std::size_t i = 0; i < screens().size(); i++) {
        if (!screens()[i].isNull() &&
            screens()[i].name().compare(name) == 0) {
            index = static_cast<int>(i);
            found = true;
            break;
        }
    }
    return found;
}

bool ServerConfig::fixNoServer(const QString& name, int& index)
{
    bool fixed = false;
    if (screens()[serverDefaultIndex].isNull()) {
        m_Screens[serverDefaultIndex].setName(name);
        index = serverDefaultIndex;
        fixed = true;
    }

    return fixed;
}

int ServerConfig::showAddClientDialog(const QString& clientName)
{
    int result = kAddClientIgnore;

    if (!m_pMainWindow->isActiveWindow()) {
        m_pMainWindow->showNormal();
        m_pMainWindow->activateWindow();
    }

    AddClientDialog addClientDialog(clientName, m_pMainWindow);
    addClientDialog.exec();
    result = addClientDialog.addResult();
    m_IgnoreAutoConfigClient = addClientDialog.ignoreAutoConfigClient();

    return result;
}

void::ServerConfig::addToFirstEmptyGrid(const QString &clientName)
{
    for (std::size_t i = 0; i < screens().size(); i++) {
        if (screens()[i].isNull()) {
            m_Screens[i].setName(clientName);
            break;
        }
    }
}

size_t ServerConfig::defaultClipboardSharingSize() {
    return 100 * 1000 * 1000; // 100 MB
}

size_t ServerConfig::setClipboardSharingSize(size_t size) {
    using std::swap;
    swap (size, m_ClipboardSharingSize);
    return size;
}
