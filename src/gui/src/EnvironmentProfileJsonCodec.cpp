/* InputLeap -- strict JSON codec for the four public environment profiles. */
#include "EnvironmentProfileJsonCodec.h"

#include <QJsonArray>
#include <QSet>
#include <QStringList>

#include <cmath>
#include <limits>
#include <utility>
#include <vector>

namespace {
using Error = EnvironmentProfileJsonCodec::Error;

Error exactKeys(const QJsonObject& object, const QStringList& required)
{
    const QSet<QString> allowed(required.begin(), required.end());
    for (const QString& key : object.keys()) {
        if (!allowed.contains(key))
            return Error::UnknownField;
    }
    for (const QString& key : required) {
        if (!object.contains(key))
            return Error::MissingField;
    }
    return Error::None;
}

bool integer(const QJsonValue& value, qint64 minimum, qint64 maximum, qint64& output)
{
    if (!value.isDouble())
        return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number ||
        number < static_cast<double>(minimum) || number > static_cast<double>(maximum)) {
        return false;
    }
    output = static_cast<qint64>(number);
    return true;
}

QJsonObject encodeRect(const QRect& rectangle)
{
    return {{QStringLiteral("x"), rectangle.x()},
            {QStringLiteral("y"), rectangle.y()},
            {QStringLiteral("width"), rectangle.width()},
            {QStringLiteral("height"), rectangle.height()}};
}

Error decodeRect(const QJsonValue& value, QRect& rectangle)
{
    if (!value.isObject())
        return Error::InvalidType;
    const QJsonObject object = value.toObject();
    const Error keys = exactKeys(object, {QStringLiteral("x"), QStringLiteral("y"),
                                          QStringLiteral("width"), QStringLiteral("height")});
    if (keys != Error::None)
        return keys;
    qint64 x = 0;
    qint64 y = 0;
    qint64 width = 0;
    qint64 height = 0;
    if (!integer(object.value(QStringLiteral("x")), -ScreenLayout::MaxCoordinate,
                 ScreenLayout::MaxCoordinate, x) ||
        !integer(object.value(QStringLiteral("y")), -ScreenLayout::MaxCoordinate,
                 ScreenLayout::MaxCoordinate, y) ||
        !integer(object.value(QStringLiteral("width")), 1, ScreenLayout::MaxExtent, width) ||
        !integer(object.value(QStringLiteral("height")), 1, ScreenLayout::MaxExtent, height)) {
        return Error::InvalidValue;
    }
    rectangle = QRect(static_cast<int>(x), static_cast<int>(y),
                      static_cast<int>(width), static_cast<int>(height));
    return Error::None;
}

QJsonObject encodeMonitor(const ScreenLayout::Monitor& monitor)
{
    return {{QStringLiteral("geometry"), encodeRect(monitor.geometry)},
            {QStringLiteral("devicePixelRatio"), monitor.devicePixelRatio},
            {QStringLiteral("orientation"), static_cast<int>(monitor.orientation)}};
}

Error decodeMonitor(const QJsonValue& value, int index, ScreenLayout::Monitor& monitor)
{
    if (!value.isObject())
        return Error::InvalidType;
    const QJsonObject object = value.toObject();
    const Error keys = exactKeys(object, {QStringLiteral("geometry"),
                                          QStringLiteral("devicePixelRatio"),
                                          QStringLiteral("orientation")});
    if (keys != Error::None)
        return keys;
    if (!object.value(QStringLiteral("devicePixelRatio")).isDouble() ||
        !object.value(QStringLiteral("orientation")).isDouble()) {
        return Error::InvalidType;
    }
    monitor.id = QStringLiteral("monitor-%1").arg(index + 1);
    Error result = decodeRect(object.value(QStringLiteral("geometry")), monitor.geometry);
    if (result != Error::None)
        return result;
    const double ratio = object.value(QStringLiteral("devicePixelRatio")).toDouble();
    qint64 orientation = 0;
    if (!std::isfinite(ratio) || ratio < 0.25 || ratio > 16.0 ||
        !integer(object.value(QStringLiteral("orientation")),
                 std::numeric_limits<int>::min(), std::numeric_limits<int>::max(), orientation)) {
        return Error::InvalidValue;
    }
    monitor.devicePixelRatio = ratio;
    monitor.orientation = static_cast<Qt::ScreenOrientation>(orientation);
    monitor.stableIdentity = false;
    return Error::None;
}

QJsonObject encodeExtensionDevice(const ScreenLayout::Device& device)
{
    QJsonArray monitors;
    for (const auto& monitor : device.monitors)
        monitors.push_back(encodeMonitor(monitor));
    return {{QStringLiteral("uuid"), device.uuid.toString(QUuid::WithoutBraces)},
            {QStringLiteral("technicalName"), device.technicalName},
            {QStringLiteral("geometry"), encodeRect(device.geometry)},
            {QStringLiteral("monitors"), monitors}};
}

bool canonicalUuid(const QJsonValue& value, QUuid& uuid)
{
    if (!value.isString())
        return false;
    const QString text = value.toString();
    uuid = QUuid(text);
    return !uuid.isNull() && text == uuid.toString(QUuid::WithoutBraces);
}

Error decodeExtensionDevice(const QJsonValue& value, ScreenLayout::Device& device)
{
    if (!value.isObject())
        return Error::InvalidType;
    const QJsonObject object = value.toObject();
    const Error keys = exactKeys(object, {QStringLiteral("uuid"), QStringLiteral("technicalName"),
                                          QStringLiteral("geometry"), QStringLiteral("monitors")});
    if (keys != Error::None)
        return keys;
    if (!canonicalUuid(object.value(QStringLiteral("uuid")), device.uuid) ||
        !object.value(QStringLiteral("technicalName")).isString() ||
        !object.value(QStringLiteral("monitors")).isArray()) {
        return Error::InvalidType;
    }
    device.technicalName = object.value(QStringLiteral("technicalName")).toString();
    Error result = decodeRect(object.value(QStringLiteral("geometry")), device.geometry);
    if (result != Error::None)
        return result;
    const QJsonArray monitors = object.value(QStringLiteral("monitors")).toArray();
    if (monitors.isEmpty() || monitors.size() > ScreenLayout::MaxMonitorsPerDevice)
        return Error::ResourceLimit;
    device.monitors.reserve(static_cast<size_t>(monitors.size()));
    for (int index = 0; index < monitors.size(); ++index) {
        ScreenLayout::Monitor monitor;
        result = decodeMonitor(monitors.at(index), index, monitor);
        if (result != Error::None)
            return result;
        device.monitors.push_back(std::move(monitor));
    }
    return Error::None;
}

QJsonObject encodeProfileDevice(const EnvironmentProfile::Device& device)
{
    return {{QStringLiteral("uuid"), device.uuid.toString(QUuid::WithoutBraces)},
            {QStringLiteral("technicalName"), device.technicalName},
            {QStringLiteral("requestedResources"), static_cast<double>(device.requestedResources)}};
}

Error decodeProfileDevice(const QJsonValue& value, EnvironmentProfile::Device& device)
{
    if (!value.isObject())
        return Error::InvalidType;
    const QJsonObject object = value.toObject();
    const Error keys = exactKeys(object, {QStringLiteral("uuid"), QStringLiteral("technicalName"),
                                          QStringLiteral("requestedResources")});
    if (keys != Error::None)
        return keys;
    if (!canonicalUuid(object.value(QStringLiteral("uuid")), device.uuid) ||
        !object.value(QStringLiteral("technicalName")).isString()) {
        return Error::InvalidType;
    }
    qint64 resources = 0;
    if (!integer(object.value(QStringLiteral("requestedResources")), 0,
                 std::numeric_limits<quint32>::max(), resources)) {
        return object.value(QStringLiteral("requestedResources")).isDouble()
                   ? Error::InvalidValue : Error::InvalidType;
    }
    device.technicalName = object.value(QStringLiteral("technicalName")).toString();
    device.requestedResources = static_cast<DevicePermissions::Mask>(resources);
    if ((device.requestedResources & ~EnvironmentProfile::ManagedResources) != 0)
        return Error::InvalidValue;
    return Error::None;
}

QJsonObject encodeProfile(const EnvironmentProfile& profile)
{
    QJsonArray grid;
    for (const QString& name : profile.layout.gridTechnicalNames)
        grid.push_back(name);
    QJsonArray extension;
    for (const auto& device : profile.layout.extension.devices())
        extension.push_back(encodeExtensionDevice(device));
    QJsonArray devices;
    for (const auto& device : profile.devices)
        devices.push_back(encodeProfileDevice(device));
    const QJsonObject layout{{QStringLiteral("columns"), profile.layout.columns},
                             {QStringLiteral("rows"), profile.layout.rows},
                             {QStringLiteral("grid"), grid},
                             {QStringLiteral("extensionDevices"), extension}};
    return {{QStringLiteral("kind"), EnvironmentProfile::key(profile.kind)},
            {QStringLiteral("layout"), layout},
            {QStringLiteral("devices"), devices}};
}

Error decodeProfile(const QJsonValue& value, EnvironmentProfile& profile)
{
    if (!value.isObject())
        return Error::InvalidType;
    const QJsonObject object = value.toObject();
    const Error keys = exactKeys(object, {QStringLiteral("kind"), QStringLiteral("layout"),
                                          QStringLiteral("devices")});
    if (keys != Error::None)
        return keys;
    if (!object.value(QStringLiteral("kind")).isString() ||
        !object.value(QStringLiteral("layout")).isObject() ||
        !object.value(QStringLiteral("devices")).isArray()) {
        return Error::InvalidType;
    }
    const auto kind = EnvironmentProfile::fromKey(object.value(QStringLiteral("kind")).toString());
    if (!kind)
        return Error::InvalidValue;
    profile.kind = *kind;

    const QJsonObject layout = object.value(QStringLiteral("layout")).toObject();
    Error result = exactKeys(layout, {QStringLiteral("columns"), QStringLiteral("rows"),
                                      QStringLiteral("grid"), QStringLiteral("extensionDevices")});
    if (result != Error::None)
        return result;
    if (!layout.value(QStringLiteral("grid")).isArray() ||
        !layout.value(QStringLiteral("extensionDevices")).isArray()) {
        return Error::InvalidType;
    }
    qint64 columns = 0;
    qint64 rows = 0;
    if (!integer(layout.value(QStringLiteral("columns")), 1, 16, columns) ||
        !integer(layout.value(QStringLiteral("rows")), 1, 16, rows)) {
        return layout.value(QStringLiteral("columns")).isDouble() &&
                       layout.value(QStringLiteral("rows")).isDouble()
                   ? Error::InvalidValue : Error::InvalidType;
    }
    profile.layout.columns = static_cast<int>(columns);
    profile.layout.rows = static_cast<int>(rows);

    const QJsonArray grid = layout.value(QStringLiteral("grid")).toArray();
    const QJsonArray extension = layout.value(QStringLiteral("extensionDevices")).toArray();
    const QJsonArray devices = object.value(QStringLiteral("devices")).toArray();
    if (grid.size() > ScreenLayout::MaxDevices || extension.size() > ScreenLayout::MaxDevices ||
        devices.size() > ScreenLayout::MaxDevices) {
        return Error::ResourceLimit;
    }
    for (const auto& name : grid) {
        if (!name.isString())
            return Error::InvalidType;
        profile.layout.gridTechnicalNames.push_back(name.toString());
    }

    std::vector<ScreenLayout::Device> extensionDevices;
    extensionDevices.reserve(static_cast<size_t>(extension.size()));
    for (const auto& deviceValue : extension) {
        ScreenLayout::Device device;
        result = decodeExtensionDevice(deviceValue, device);
        if (result != Error::None)
            return result;
        extensionDevices.push_back(std::move(device));
    }
    profile.layout.extension = ScreenLayout(std::move(extensionDevices));

    for (const auto& deviceValue : devices) {
        EnvironmentProfile::Device device;
        result = decodeProfileDevice(deviceValue, device);
        if (result != Error::None)
            return result;
        profile.devices.push_back(std::move(device));
    }
    return profile.isValid() ? Error::None : Error::InvalidValue;
}
}

QJsonObject EnvironmentProfileJsonCodec::encode(const Collection& collection)
{
    QJsonArray profiles;
    for (const auto& profile : collection.profiles)
        profiles.push_back(encodeProfile(profile));
    return {{QStringLiteral("activeKind"), EnvironmentProfile::key(collection.activeKind)},
            {QStringLiteral("profiles"), profiles}};
}

EnvironmentProfileJsonCodec::DecodeResult
EnvironmentProfileJsonCodec::decode(const QJsonObject& object)
{
    Error result = exactKeys(object, {QStringLiteral("activeKind"), QStringLiteral("profiles")});
    if (result != Error::None)
        return {result, std::nullopt};
    if (!object.value(QStringLiteral("activeKind")).isString() ||
        !object.value(QStringLiteral("profiles")).isArray()) {
        return {Error::InvalidType, std::nullopt};
    }
    const auto active = EnvironmentProfile::fromKey(object.value(QStringLiteral("activeKind")).toString());
    if (!active)
        return {Error::InvalidValue, std::nullopt};
    const QJsonArray profiles = object.value(QStringLiteral("profiles")).toArray();
    if (profiles.size() != EnvironmentProfile::canonicalKinds().size())
        return {Error::InvalidValue, std::nullopt};

    Collection collection;
    collection.activeKind = *active;
    QSet<EnvironmentProfile::Kind> kinds;
    for (const auto& profileValue : profiles) {
        EnvironmentProfile profile;
        result = decodeProfile(profileValue, profile);
        if (result != Error::None)
            return {result, std::nullopt};
        if (kinds.contains(profile.kind))
            return {Error::InvalidValue, std::nullopt};
        kinds.insert(profile.kind);
        collection.profiles.push_back(std::move(profile));
    }
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        if (!kinds.contains(kind))
            return {Error::InvalidValue, std::nullopt};
    }
    if (!kinds.contains(collection.activeKind))
        return {Error::InvalidValue, std::nullopt};
    return {Error::None, std::move(collection)};
}
