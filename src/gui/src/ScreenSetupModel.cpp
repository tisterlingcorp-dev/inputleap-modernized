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

#include "ScreenSetupModel.h"
#include "Screen.h"

#include <QtCore>
#include <QtGui>
#include <algorithm>
#include <cmath>
#include <QSet>

namespace {
constexpr int kLayoutSchemaVersion = 2;
const QUuid kLegacyLayoutNamespace("{0c1bb276-b895-51ff-87f6-6f9cf2eebf49}");

bool withinLimits(const QRect& rect)
{
    if (rect.width() <= 0 || rect.height() <= 0)
        return false;
    const qint64 left = rect.x(), top = rect.y();
    const qint64 right = left + rect.width(), bottom = top + rect.height();
    return std::abs(left) <= ScreenLayout::MaxCoordinate &&
           std::abs(top) <= ScreenLayout::MaxCoordinate &&
           std::abs(right) <= ScreenLayout::MaxCoordinate &&
           std::abs(bottom) <= ScreenLayout::MaxCoordinate &&
           rect.width() <= ScreenLayout::MaxExtent && rect.height() <= ScreenLayout::MaxExtent;
}

bool touches(const QRect& a, const QRect& b)
{
    const bool vertical = (a.right() + 1 == b.left() || b.right() + 1 == a.left()) &&
                          std::max(a.top(), b.top()) <= std::min(a.bottom(), b.bottom());
    const bool horizontal = (a.bottom() + 1 == b.top() || b.bottom() + 1 == a.top()) &&
                            std::max(a.left(), b.left()) <= std::min(a.right(), b.right());
    return vertical || horizontal;
}

void addIssue(ScreenLayout::Validation& result, ScreenLayout::Issue issue)
{
    result.add(issue);
}

bool isValidMetadataGroup(const QString& group)
{
    if (group.isEmpty()) return false;

    bool componentHasCharacter = false;
    for (const QChar character : group) {
        if (character == QLatin1Char('/')) {
            if (!componentHasCharacter) return false;
            componentHasCharacter = false;
            continue;
        }

        const ushort code = character.unicode();
        const bool isAsciiLetter = (code >= 'A' && code <= 'Z') || (code >= 'a' && code <= 'z');
        const bool isAsciiDigit = code >= '0' && code <= '9';
        if (!isAsciiLetter && !isAsciiDigit && code != '_' && code != '-') return false;
        componentHasCharacter = true;
    }

    return componentHasCharacter;
}

QString asciiCaselessKey(const QString& value)
{
    QString key = value;
    for (QChar& character : key) {
        const ushort code = character.unicode();
        if (code >= 'A' && code <= 'Z') character = QChar(code + ('a' - 'A'));
    }
    return key;
}
}

bool ScreenLayout::Validation::has(Issue issue) const
{
    return std::find(issues_.begin(), issues_.end(), issue) != issues_.end();
}

void ScreenLayout::Validation::add(Issue issue)
{
    if (!has(issue)) issues_.push_back(issue);
}

ScreenLayout::Validation ScreenLayout::validate() const
{
    Validation result;
    if (devices_.size() > MaxDevices) {
        addIssue(result, Issue::ResourceLimit);
        return result;
    }
    for (const auto& device : devices_) {
        if (device.monitors.size() > MaxMonitorsPerDevice) {
            addIssue(result, Issue::ResourceLimit);
            return result;
        }
    }
    QSet<QUuid> uuids;
    std::vector<QRect> rectangles;
    for (const auto& device : devices_) {
        if (device.technicalName.isEmpty() || device.technicalName.toUtf8().size() > MaxTechnicalNameBytes)
            addIssue(result, Issue::ResourceLimit);
        if (device.uuid.isNull()) addIssue(result, Issue::NullUuid);
        else if (uuids.contains(device.uuid)) addIssue(result, Issue::DuplicateUuid);
        else uuids.insert(device.uuid);
        if (device.geometry.width() <= 0 || device.geometry.height() <= 0)
            addIssue(result, Issue::InvalidRectangle);
        if (!withinLimits(device.geometry)) addIssue(result, Issue::ResourceLimit);
        const QRect monitorBounds(QPoint(0, 0), device.geometry.size());
        QSet<QString> monitorIds;
        for (const auto& monitor : device.monitors) {
            if (monitor.id.toUtf8().size() > MaxMonitorIdBytes) addIssue(result, Issue::ResourceLimit);
            if (monitor.id.isEmpty() || monitorIds.contains(monitor.id))
                addIssue(result, Issue::DuplicateMonitorId);
            monitorIds.insert(monitor.id);
            if (monitor.geometry.width() <= 0 || monitor.geometry.height() <= 0)
                addIssue(result, Issue::InvalidRectangle);
            if (!withinLimits(monitor.geometry) || monitor.geometry.x() < 0 || monitor.geometry.y() < 0)
                addIssue(result, Issue::ResourceLimit);
            if (!monitorBounds.contains(monitor.geometry))
                addIssue(result, Issue::InvalidRectangle);
            if(!std::isfinite(monitor.devicePixelRatio)||monitor.devicePixelRatio<0.25||monitor.devicePixelRatio>16.0)
                addIssue(result,Issue::ResourceLimit);
            if(monitor.orientation!=Qt::PrimaryOrientation&&monitor.orientation!=Qt::LandscapeOrientation&&
               monitor.orientation!=Qt::PortraitOrientation&&monitor.orientation!=Qt::InvertedLandscapeOrientation&&
               monitor.orientation!=Qt::InvertedPortraitOrientation)addIssue(result,Issue::ResourceLimit);
        }
        for (std::size_t i = 0; i < device.monitors.size(); ++i)
            for (std::size_t j = i + 1; j < device.monitors.size(); ++j)
                if (device.monitors[i].geometry.intersects(device.monitors[j].geometry))
                    addIssue(result, Issue::Collision);
        rectangles.push_back(device.geometry);
    }
    for (std::size_t i = 0; i < rectangles.size(); ++i)
        for (std::size_t j = i + 1; j < rectangles.size(); ++j)
            if (rectangles[i].intersects(rectangles[j])) addIssue(result, Issue::Collision);

    if (rectangles.size() > 1) {
        std::vector<bool> reached(rectangles.size()); reached[0] = true;
        bool changed = true;
        while (changed) {
            changed = false;
            for (std::size_t i = 0; i < rectangles.size(); ++i) if (reached[i])
                for (std::size_t j = 0; j < rectangles.size(); ++j)
                    if (!reached[j] && touches(rectangles[i], rectangles[j])) { reached[j] = true; changed = true; }
        }
        if (std::find(reached.begin(), reached.end(), false) != reached.end()) addIssue(result, Issue::Disconnected);
    }
    return result;
}

ScreenLayout ScreenLayout::repaired() const
{
    ScreenLayout result = *this;
    if (result.devices_.size() > MaxDevices) return result;
    for (std::size_t i = 0; i < result.devices_.size(); ++i) {
        auto& device = result.devices_[i];
        const int width = std::clamp(device.geometry.width(), 1, MaxExtent);
        const int height = std::clamp(device.geometry.height(), 1, MaxExtent);
        const int x = std::clamp(device.geometry.x(), -MaxCoordinate, MaxCoordinate - width);
        const int y = std::clamp(device.geometry.y(), -MaxCoordinate, MaxCoordinate - height);
        device.geometry = QRect((x / 10) * 10, (y / 10) * 10, width, height);
        const QRect monitorBounds(QPoint(0, 0), device.geometry.size());
        std::vector<QRect> monitorRectangles;
        for (auto& monitor : device.monitors) {
            if(!std::isfinite(monitor.devicePixelRatio)||monitor.devicePixelRatio<0.25||monitor.devicePixelRatio>16.0)monitor.devicePixelRatio=1.0;
            if(monitor.orientation!=Qt::PrimaryOrientation&&monitor.orientation!=Qt::LandscapeOrientation&&monitor.orientation!=Qt::PortraitOrientation&&monitor.orientation!=Qt::InvertedLandscapeOrientation&&monitor.orientation!=Qt::InvertedPortraitOrientation)monitor.orientation=Qt::PrimaryOrientation;
            const bool originalUsable=withinLimits(monitor.geometry)&&monitorBounds.contains(monitor.geometry);
            int monitorWidth=std::clamp(monitor.geometry.width(),1,device.geometry.width());
            int monitorHeight=std::clamp(monitor.geometry.height(),1,device.geometry.height());
            int monitorX=std::clamp(monitor.geometry.x(),0,device.geometry.width()-monitorWidth);
            int monitorY=std::clamp(monitor.geometry.y(),0,device.geometry.height()-monitorHeight);
            QRect candidate=originalUsable?monitor.geometry:QRect(monitorX,monitorY,monitorWidth,monitorHeight);
            const auto free=[&](const QRect& value){return std::none_of(monitorRectangles.begin(),monitorRectangles.end(),[&](const QRect& other){return value.intersects(other);});};
            if(!free(candidate)){
                bool placed=false;
                for(const auto& anchor:monitorRectangles){
                    for(const QPoint point:{QPoint(anchor.right()+1,anchor.top()),QPoint(anchor.left()-candidate.width(),anchor.top()),QPoint(anchor.left(),anchor.bottom()+1),QPoint(anchor.left(),anchor.top()-candidate.height())}){
                        QRect alternative(point,candidate.size());
                        if(QRect(QPoint(0,0),device.geometry.size()).contains(alternative)&&free(alternative)){candidate=alternative;placed=true;break;}
                    }
                    if(placed)break;
                }
            }
            monitor.geometry=candidate;monitorRectangles.push_back(candidate);
        }
        bool usable = i == 0;
        if (i > 0) {
            bool collision = false, connected = false;
            for (std::size_t j = 0; j < i; ++j) {
                collision |= device.geometry.intersects(result.devices_[j].geometry);
                connected |= touches(device.geometry, result.devices_[j].geometry);
            }
            usable = !collision && connected;
        }
        if (!usable) {
            bool placed=false;
            for(std::size_t j=0;j<i&&!placed;++j){
                const QRect& anchor=result.devices_[j].geometry;
                const QList<QPoint> candidates={{anchor.right()+1,anchor.top()},{anchor.left()-device.geometry.width(),anchor.top()},{anchor.left(),anchor.bottom()+1},{anchor.left(),anchor.top()-device.geometry.height()}};
                for(const QPoint& point:candidates){
                    QRect alternative(point,device.geometry.size());
                    if(!withinLimits(alternative))continue;
                    bool collision=false;for(std::size_t k=0;k<i;++k)collision|=alternative.intersects(result.devices_[k].geometry);
                    if(!collision){device.geometry=alternative;placed=true;break;}
                }
            }
        }
    }
    return result;
}

bool ScreenLayout::updateMonitorsForDevice(const QUuid& uuid,std::vector<Monitor> monitors)
{
    if(uuid.isNull()||monitors.empty()||monitors.size()>MaxMonitorsPerDevice)return false;
    auto found=std::find_if(devices_.begin(),devices_.end(),[&](const Device& d){return d.uuid==uuid;});
    if(found==devices_.end())return false;
    Device candidate=*found;candidate.monitors=std::move(monitors);
    ScreenLayout check({candidate});const auto validation=check.validate();
    if(!validation.isValid())return false;
    found->monitors=std::move(candidate.monitors);return true;
}

bool ScreenLayout::bindLocalDevice(const QUuid& uuid,const QString& technicalName,std::vector<Monitor> monitors)
{
    if(uuid.isNull()||technicalName.isEmpty()||monitors.empty())return false;
    ScreenLayout candidate=*this;
    auto found=std::find_if(candidate.devices_.begin(),candidate.devices_.end(),[&](const Device& d){return d.uuid==uuid;});
    if(found==candidate.devices_.end()){
        if(std::count_if(candidate.devices_.begin(),candidate.devices_.end(),[&](const Device& d){return d.technicalName==technicalName;})!=1)return false;
        found=std::find_if(candidate.devices_.begin(),candidate.devices_.end(),[&](const Device& d){return d.technicalName==technicalName;});found->uuid=uuid;
    }
    if(!candidate.updateMonitorsForDevice(uuid,std::move(monitors)))return false;
    *this=std::move(candidate);return true;
}

ScreenLayout ScreenLayout::synchronizedToLegacyGrid(const QStringList& names, int columns, int rows, const QStringList& previousNames) const
{
    if (columns <= 0 || rows <= 0 || names.size() > MaxDevices) return {};
    std::vector<Device> synchronized;
    for (int i = 0; i < names.size() && i < columns * rows; ++i) {
        if (names[i].isEmpty()) continue;
        auto existing = std::find_if(devices_.begin(), devices_.end(), [&](const Device& item) {
            return item.technicalName.compare(names[i], Qt::CaseInsensitive) == 0;
        });
        if(existing==devices_.end()&&i<previousNames.size()&&!previousNames[i].isEmpty())existing=std::find_if(devices_.begin(),devices_.end(),[&](const Device& item){return item.technicalName==previousNames[i];});
        Device device;
        if (existing != devices_.end()) { device = *existing; device.technicalName=names[i]; }
        else { device.uuid = QUuid::createUuidV5(kLegacyLayoutNamespace, names[i].toUtf8()); device.technicalName = names[i]; }
        device.geometry = QRect((i % columns) * 100, (i / columns) * 100, 100, 100);
        synchronized.push_back(std::move(device));
    }
    return ScreenLayout(std::move(synchronized)).repaired();
}

std::optional<ScreenLayout> ScreenLayout::synchronizedToLegacyGridWithExistingIdentity(
    const QStringList& names, int columns, int rows) const
{
    if (columns <= 0 || rows <= 0 || names.size() > MaxDevices ||
        names.size() != qsizetype(columns) * rows) return std::nullopt;

    QHash<QString, int> deviceByName;
    QSet<QUuid> deviceUuids;
    for (int i = 0; i < static_cast<int>(devices_.size()); ++i) {
        const Device& device = devices_[static_cast<size_t>(i)];
        const QString key = asciiCaselessKey(device.technicalName);
        if (device.uuid.isNull() || key.isEmpty() || deviceUuids.contains(device.uuid) ||
            deviceByName.contains(key)) return std::nullopt;
        deviceUuids.insert(device.uuid);
        deviceByName.insert(key, i);
    }

    QSet<QString> gridNames;
    QSet<int> boundDevices;
    std::vector<Device> synchronized;
    synchronized.reserve(devices_.size());
    for (int i = 0; i < names.size(); ++i) {
        if (names[i].isEmpty()) continue;
        const QString key = asciiCaselessKey(names[i]);
        if (gridNames.contains(key) || !deviceByName.contains(key)) return std::nullopt;
        gridNames.insert(key);
        const int deviceIndex = deviceByName.value(key);
        if (boundDevices.contains(deviceIndex)) return std::nullopt;
        boundDevices.insert(deviceIndex);
        Device device = devices_[static_cast<size_t>(deviceIndex)];
        device.technicalName = names[i];
        device.geometry = QRect((i % columns) * 100, (i / columns) * 100, 100, 100);
        synchronized.push_back(std::move(device));
    }
    if (boundDevices.size() != static_cast<int>(devices_.size())) return std::nullopt;

    ScreenLayout result = ScreenLayout(std::move(synchronized)).repaired();
    if (!result.validate().isValid()) return std::nullopt;
    return result;
}

ScreenLayout ScreenLayout::fromLegacyGrid(const QStringList& names, int columns, int rows)
{
    std::vector<Device> devices;
    if (columns <= 0 || rows <= 0 || names.size() > MaxDevices) return ScreenLayout(devices);
    for (int i = 0; i < names.size() && i < columns * rows; ++i) {
        if (names[i].isEmpty()) continue;
        Device d;
        d.uuid = QUuid::createUuidV5(kLegacyLayoutNamespace, names[i].toUtf8());
        d.technicalName = names[i];
        d.geometry = QRect((i % columns) * 100, (i / columns) * 100, 100, 100);
        d.monitors.push_back({QStringLiteral("logical-default"),QRect(0,0,100,100),1.0,Qt::PrimaryOrientation,false});
        devices.push_back(std::move(d));
    }
    return ScreenLayout(std::move(devices));
}

bool ScreenLayout::saveMetadata(QSettings& settings, const QString& group, bool synchronize) const
{
    if (!isValidMetadataGroup(group)) return false;
    const auto validation=validate();
    if(!validation.isValid())return false;
    settings.beginGroup(group);
    settings.remove("");
    settings.setValue("schemaVersion", kLayoutSchemaVersion);
    settings.beginWriteArray("devices");
    for (int i = 0; i < static_cast<int>(devices_.size()) && i < MaxDevices; ++i) {
        settings.setArrayIndex(i);
        const auto& d = devices_[i];
        settings.setValue("uuid", d.uuid.toString(QUuid::WithoutBraces));
        settings.setValue("technicalName", d.technicalName);
        settings.setValue("geometry", d.geometry);
        settings.beginWriteArray("monitors");
        for (int j = 0; j < static_cast<int>(d.monitors.size()) && j < MaxMonitorsPerDevice; ++j) {
            settings.setArrayIndex(j); settings.setValue("id", d.monitors[j].id); settings.setValue("geometry", d.monitors[j].geometry);
            settings.setValue("devicePixelRatio",
                              QString::number(d.monitors[j].devicePixelRatio, 'g', 17));
            settings.setValue("orientation",static_cast<int>(d.monitors[j].orientation));
            settings.setValue("stableIdentity",d.monitors[j].stableIdentity ? 1 : 0);
        }
        settings.endArray();
    }
    settings.endArray(); settings.endGroup();
    if (synchronize) settings.sync();
    return settings.status() == QSettings::NoError;
}

std::optional<ScreenLayout> ScreenLayout::loadMetadata(QSettings& settings, const QString& group)
{
    if (!isValidMetadataGroup(group)) return std::nullopt;
    settings.beginGroup(group);
    if (!settings.contains("schemaVersion")) { settings.endGroup(); return std::nullopt; }
    const int schemaVersion=settings.value("schemaVersion").toInt();
    if (schemaVersion < 1 || schemaVersion > kLayoutSchemaVersion) { settings.endGroup(); return std::nullopt; }
    const int count = settings.beginReadArray("devices");
    if (count < 0 || count > MaxDevices) { settings.endArray(); settings.endGroup(); return std::nullopt; }
    std::vector<Device> devices;
    for (int i = 0; i < count; ++i) {
        settings.setArrayIndex(i); Device d;
        const QString persistedUuid = settings.value("uuid").toString();
        const QUuid parsedUuid(persistedUuid);
        if (persistedUuid.size() != 36 || parsedUuid.isNull() ||
            parsedUuid.toString(QUuid::WithoutBraces) != persistedUuid) {
            settings.endArray(); settings.endGroup(); return std::nullopt;
        }
        d.uuid = parsedUuid; d.technicalName = settings.value("technicalName").toString(); d.geometry = settings.value("geometry").toRect();
        const int monitors = settings.beginReadArray("monitors");
        if (monitors < 0 || monitors > MaxMonitorsPerDevice) { settings.endArray(); settings.endArray(); settings.endGroup(); return std::nullopt; }
        for (int j = 0; j < monitors; ++j) { settings.setArrayIndex(j);
            d.monitors.push_back({settings.value("id").toString(),settings.value("geometry").toRect(),
                schemaVersion>=2?settings.value("devicePixelRatio",1.0).toDouble():1.0,
                schemaVersion>=2?static_cast<Qt::ScreenOrientation>(settings.value("orientation",static_cast<int>(Qt::PrimaryOrientation)).toInt()):Qt::PrimaryOrientation,
                schemaVersion>=2?settings.value("stableIdentity",false).toBool():false}); }
        if(d.monitors.empty()) d.monitors.push_back({QStringLiteral("logical-default"),QRect(QPoint(0,0),d.geometry.size()),1.0,Qt::PrimaryOrientation,false});
        settings.endArray(); devices.push_back(std::move(d));
    }
    settings.endArray(); settings.endGroup();
    ScreenLayout layout(std::move(devices));
    const auto validation=layout.validate();
    if(!validation.isValid())return std::nullopt;
    return layout;
}

const QString ScreenSetupModel::m_MimeType = "application/x-input-leap-screen";

ScreenSetupModel::ScreenSetupModel(std::vector<Screen>& screens, int numColumns, int numRows) :
    QAbstractTableModel(nullptr),
    m_Screens(screens),
    m_NumColumns(numColumns),
    m_NumRows(numRows)
{
    if (static_cast<std::size_t>(m_NumColumns * m_NumRows) > screens.size())
        qFatal("Not enough elements (%zu) in screens QList for %d columns and %d rows", screens.size(), m_NumColumns, m_NumRows);
}

QVariant ScreenSetupModel::data(const QModelIndex& index, int role) const
{
    if (index.isValid() && index.row() < m_NumRows && index.column() < m_NumColumns)
    {
        switch(role)
        {
            case Qt::DecorationRole:
                if (screen(index).isNull())
                    break;
                return QIcon(*screen(index).pixmap());

            case Qt::ToolTipRole:
                if (screen(index).isNull())
                    break;
                return QString(tr(
                            "<center>Screen: <b>%1</b></center>"
                            "<br>Double click to edit settings"
                            "<br>Drag screen to the trashcan to remove it")).arg(screen(index).name());

            case Qt::DisplayRole:
                if (screen(index).isNull())
                    break;
                return screen(index).name();
        default:
            break;
        }
    }

    return QVariant();
}

Qt::ItemFlags ScreenSetupModel::flags(const QModelIndex& index) const
{
    if (!index.isValid() || index.row() >= m_NumRows || index.column() >= m_NumColumns) {
#if QT_VERSION >= QT_VERSION_CHECK(5,15,0)
        return Qt::ItemFlags();
#else
        return nullptr;
#endif
    }

    if (!screen(index).isNull())
        return Qt::ItemIsEnabled | Qt::ItemIsDragEnabled | Qt::ItemIsSelectable | Qt::ItemIsDropEnabled;

    return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDropEnabled;
}

Qt::DropActions ScreenSetupModel::supportedDropActions() const
{
    return Qt::MoveAction | Qt::CopyAction;
}

QStringList ScreenSetupModel::mimeTypes() const
{
    return QStringList() << m_MimeType;
}

QMimeData* ScreenSetupModel::mimeData(const QModelIndexList& indexes) const
{
    QMimeData* pMimeData = new QMimeData();
    QByteArray encodedData;

    QDataStream stream(&encodedData, QIODevice::WriteOnly);

    for (const QModelIndex& index : indexes) {
        if (index.isValid())
            stream << index.column() << index.row() << screen(index);
    }

    pMimeData->setData(m_MimeType, encodedData);

    return pMimeData;
}

bool ScreenSetupModel::dropMimeData(const QMimeData* data, Qt::DropAction action, int row, int column, const QModelIndex& parent)
{
    if (action == Qt::IgnoreAction)
        return true;

    if (!data->hasFormat(m_MimeType))
        return false;

     if (!parent.isValid() || row != -1 || column != -1)
        return false;

    QByteArray encodedData = data->data(m_MimeType);
    QDataStream stream(&encodedData, QIODevice::ReadOnly);

    int sourceColumn = -1;
    int sourceRow = -1;

    stream >> sourceColumn;
    stream >> sourceRow;

    // don't drop screen onto itself
    if (sourceColumn == parent.column() && sourceRow == parent.row())
        return false;

    Screen droppedScreen;
    stream >> droppedScreen;

    Screen oldScreen = screen(parent.column(), parent.row());
    if (!oldScreen.isNull() && sourceColumn != -1 && sourceRow != -1)
    {
        // mark the screen so it isn't deleted after the dragndrop succeeded
        // see ScreenSetupView::startDrag()
        oldScreen.setSwapped(true);
        screen(sourceColumn, sourceRow) = oldScreen;
    }

    screen(parent.column(), parent.row()) = droppedScreen;

    return true;
}
