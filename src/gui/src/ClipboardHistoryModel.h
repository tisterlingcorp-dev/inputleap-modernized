#pragma once

#include <QAbstractListModel>
#include <QByteArray>
#include <QImage>
#include <QString>
#include <functional>
#include "ClipboardProtectionPolicy.h"

class QMimeData;

class ClipboardHistoryModel final : public QAbstractListModel
{
    Q_OBJECT
public:
    enum class Type { Text, Image };
    enum Role {
        TypeRole = Qt::UserRole + 1,
        TimestampRole,
        PinnedRole,
        PayloadBytesRole
    };
    struct Limits {
        int maxItems = 50;
        qsizetype maxItemBytes = 4 * 1024 * 1024;
        qsizetype maxTotalBytes = 16 * 1024 * 1024;
        qint64 expiryMs = 60 * 60 * 1000;
        int maxImageWidth = 4096;
        int maxImageHeight = 4096;
        qint64 maxImagePixels = 16 * 1024 * 1024;
    };
    struct Entry {
        Type type = Type::Text;
        QString text;
        QByteArray imagePng;
        QSize imageSize;
        qint64 capturedAtMs = 0;
        bool pinned = false;
        qsizetype payloadBytes = 0;
    };
    using Clock = std::function<qint64()>;

    explicit ClipboardHistoryModel(QObject* parent = nullptr);
    explicit ClipboardHistoryModel(Clock clock, QObject* parent = nullptr);
    explicit ClipboardHistoryModel(Clock clock, Limits limits, QObject* parent = nullptr);
    ~ClipboardHistoryModel() override;

    bool isEnabled() const { return enabled_; }
    void setEnabled(bool enabled);
    bool addText(const QString& text);
    bool addImage(const QImage& image);
    bool addMimeData(const QMimeData& mimeData);
    bool addProtectedMimeData(const QMimeData& mimeData, const ClipboardProtectionPolicy::Metadata& metadata);
    void setCapturePaused(bool paused) { protection_.setPaused(paused); captureSuppressed_ = paused; }
    bool isCapturePaused() const { return protection_.paused(); }
    QString captureStateLabel() const { return protection_.stateLabel(); }
    void setCaptureSuppressed(bool suppressed) { captureSuppressed_ = suppressed; }
    bool setPinned(int row, bool pinned);
    void expire();
    void clear();
    const Entry* entry(int row) const;
    int rowCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

Q_SIGNALS:
    void enabledChanged(bool enabled);

private:
    bool addEntry(Entry entry);
    void removeRowSecure(int row);
    static void wipe(Entry& entry);
    QString preview(const Entry& entry) const;

    Clock clock_;
    Limits limits_;
    QList<Entry> entries_;
    qsizetype totalBytes_ = 0;
    bool enabled_ = false;
    bool captureSuppressed_ = false;
    ClipboardProtectionPolicy protection_;
};
