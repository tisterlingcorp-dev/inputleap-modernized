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

#pragma once

#include <QAbstractTableModel>
#include <QList>
#include <QString>
#include <QStringList>
#include <QRect>
#include <QUuid>
#include <optional>
#include <vector>

#include "Screen.h"
#include "inputleap/protocol_types.h"

class ScreenSetupView;
class ServerConfigDialog;
class QSettings;

// Pure domain model used by the current grid and by the future visual editor.
// technicalName remains the core protocol/config transport key; uuid is the
// persistent identity and is deliberately kept in GUI-only extension metadata.
class ScreenLayout
{
public:
    static constexpr int MaxDevices = 128;
    static constexpr int MaxMonitorsPerDevice = 16;
    static constexpr int MaxCoordinate = 1000000;
    static constexpr int MaxExtent = 100000;
    // The core hello reply is capped at 1024 bytes. After "Barrier", two
    // 16-bit versions, and the uint32 string length, 1009 bytes remain.
    static constexpr int MaxTechnicalNameBytes =
        static_cast<int>(inputleap::kMaxHelloLength) - 7 - 2 - 2 - 4;
    static constexpr int MaxMonitorIdBytes = 128;

    struct Monitor {
        QString id;
        QRect geometry;
        qreal devicePixelRatio = 1.0;
        Qt::ScreenOrientation orientation = Qt::PrimaryOrientation;
        bool stableIdentity = false;
    };
    struct Device {
        QUuid uuid;
        QString technicalName;
        QRect geometry;
        std::vector<Monitor> monitors;
    };
    enum class Issue {
        NullUuid, DuplicateUuid, InvalidRectangle, Collision,
        Disconnected, DuplicateMonitorId, ResourceLimit
    };
    class Validation {
    public:
        bool isValid() const { return issues_.empty(); }
        bool has(Issue issue) const;
        void add(Issue issue);
    private:
        friend class ScreenLayout;
        std::vector<Issue> issues_;
    };

    ScreenLayout() = default;
    explicit ScreenLayout(std::vector<Device> devices) : devices_(std::move(devices)) {}
    const std::vector<Device>& devices() const { return devices_; }
    void swap(ScreenLayout& other) noexcept { devices_.swap(other.devices_); }
    Validation validate() const;
    ScreenLayout repaired() const;
    bool updateMonitorsForDevice(const QUuid& uuid,std::vector<Monitor> monitors);
    bool bindLocalDevice(const QUuid& uuid,const QString& technicalName,std::vector<Monitor> monitors);
    ScreenLayout synchronizedToLegacyGrid(const QStringList& names, int columns, int rows, const QStringList& previousNames = {}) const;
    std::optional<ScreenLayout> synchronizedToLegacyGridWithExistingIdentity(
        const QStringList& names, int columns, int rows) const;

    static ScreenLayout fromLegacyGrid(const QStringList& names, int columns, int rows);
    bool saveMetadata(
        QSettings& settings,
        const QString& group = QStringLiteral("screenLayoutExtension"),
        bool synchronize = true) const;
    static std::optional<ScreenLayout> loadMetadata(
        QSettings& settings,
        const QString& group = QStringLiteral("screenLayoutExtension"));

private:
    std::vector<Device> devices_;
};

class ScreenSetupModel : public QAbstractTableModel
{
    Q_OBJECT

    friend class ScreenSetupView;
    friend class ServerConfigDialog;

    public:
        ScreenSetupModel(std::vector<Screen>& screens, int numColumns, int numRows);

    public:
        static const QString& mimeType() { return m_MimeType; }
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
        int rowCount() const { return m_NumRows; }
        int columnCount() const { return m_NumColumns; }
        int rowCount(const QModelIndex&) const override { return rowCount(); }
        int columnCount(const QModelIndex&) const override { return columnCount(); }
        Qt::DropActions supportedDropActions() const override;
        Qt::ItemFlags flags(const QModelIndex& index) const override;
        QStringList mimeTypes() const override;
        QMimeData* mimeData(const QModelIndexList& indexes) const override;

    protected:
        bool dropMimeData(const QMimeData* data, Qt::DropAction action, int row, int column, const QModelIndex& parent) override;
        const Screen& screen(const QModelIndex& index) const { return screen(index.column(), index.row()); }
        Screen& screen(const QModelIndex& index) { return screen(index.column(), index.row()); }
        const Screen& screen(int column, int row) const { return m_Screens[row * m_NumColumns + column]; }
        Screen& screen(int column, int row) { return m_Screens[row * m_NumColumns + column]; }

    private:
        std::vector<Screen>& m_Screens;
        const int m_NumColumns;
        const int m_NumRows;

        static const QString m_MimeType;
};
