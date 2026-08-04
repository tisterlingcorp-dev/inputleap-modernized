#include "ClipboardHistoryModel.h"

#include <QBuffer>
#include <QDateTime>
#include <QMimeData>
#include <utility>

ClipboardHistoryModel::ClipboardHistoryModel(QObject* parent) :
    ClipboardHistoryModel([] { return QDateTime::currentMSecsSinceEpoch(); }, {}, parent)
{
}

ClipboardHistoryModel::ClipboardHistoryModel(Clock clock, QObject* parent) :
    ClipboardHistoryModel(std::move(clock), {}, parent)
{
}

ClipboardHistoryModel::ClipboardHistoryModel(Clock clock, Limits limits, QObject* parent) :
    QAbstractListModel(parent),
    clock_(std::move(clock)),
    limits_(limits)
{
}

ClipboardHistoryModel::~ClipboardHistoryModel()
{
    clear();
}

void ClipboardHistoryModel::setEnabled(bool enabled)
{
    if (enabled_ == enabled) return;
    enabled_ = enabled;
    if (!enabled_) clear();
    emit enabledChanged(enabled_);
}

bool ClipboardHistoryModel::addText(const QString& text)
{
    if (!enabled_ || text.isEmpty()) return false;
    const QByteArray utf8 = text.toUtf8();
    if (utf8.isEmpty()) return false;
    Entry entry;
    entry.type = Type::Text;
    entry.text = text;
    entry.payloadBytes = utf8.size();
    entry.capturedAtMs = clock_();
    return addEntry(std::move(entry));
}

bool ClipboardHistoryModel::addImage(const QImage& image)
{
    if (!enabled_ || image.isNull() || image.width() <= 0 || image.height() <= 0 ||
        image.width() > limits_.maxImageWidth || image.height() > limits_.maxImageHeight ||
        qint64(image.width()) * qint64(image.height()) > limits_.maxImagePixels ||
        image.sizeInBytes() > limits_.maxItemBytes) return false;
    QByteArray png;
    QBuffer buffer(&png);
    if (!buffer.open(QIODevice::WriteOnly) || !image.save(&buffer, "PNG") || png.isEmpty()) return false;
    Entry entry;
    entry.type = Type::Image;
    entry.imagePng = std::move(png);
    entry.imageSize = image.size();
    entry.payloadBytes = entry.imagePng.size();
    entry.capturedAtMs = clock_();
    return addEntry(std::move(entry));
}

bool ClipboardHistoryModel::addMimeData(const QMimeData& mimeData)
{
    if (!enabled_ || captureSuppressed_ || mimeData.hasUrls()) return false;
    if (mimeData.hasImage()) {
        const QVariant value = mimeData.imageData();
        if (value.canConvert<QImage>()) return addImage(qvariant_cast<QImage>(value));
        return false;
    }
    if (mimeData.hasText()) return addText(mimeData.text());
    return false;
}

bool ClipboardHistoryModel::addProtectedMimeData(const QMimeData& mimeData,
    const ClipboardProtectionPolicy::Metadata& metadata)
{
    if (!protection_.accept(metadata, mimeData.text())) return false;
    return addMimeData(mimeData);
}

bool ClipboardHistoryModel::addEntry(Entry candidate)
{
    expire();
    if (candidate.payloadBytes <= 0 || candidate.payloadBytes > limits_.maxItemBytes ||
        candidate.payloadBytes > limits_.maxTotalBytes || limits_.maxItems <= 0) {
        wipe(candidate);
        return false;
    }
    if (!entries_.isEmpty()) {
        Entry& latest = entries_.front();
        const bool same = latest.type == candidate.type &&
            ((candidate.type == Type::Text && latest.text == candidate.text) ||
             (candidate.type == Type::Image && latest.imagePng == candidate.imagePng));
        if (same) {
            latest.capturedAtMs = candidate.capturedAtMs;
            wipe(candidate);
            emit dataChanged(index(0), index(0), {TimestampRole});
            return true;
        }
    }
    while (entries_.size() >= limits_.maxItems || totalBytes_ + candidate.payloadBytes > limits_.maxTotalBytes) {
        int victim = -1;
        for (int i = entries_.size() - 1; i >= 0; --i) {
            if (!entries_.at(i).pinned) { victim = i; break; }
        }
        if (victim < 0) {
            wipe(candidate);
            return false;
        }
        removeRowSecure(victim);
    }
    beginInsertRows({}, 0, 0);
    totalBytes_ += candidate.payloadBytes;
    entries_.prepend(std::move(candidate));
    endInsertRows();
    return true;
}

bool ClipboardHistoryModel::setPinned(int row, bool pinned)
{
    if (row < 0 || row >= entries_.size()) return false;
    if (entries_[row].pinned == pinned) return true;
    entries_[row].pinned = pinned;
    emit dataChanged(index(row), index(row), {PinnedRole, Qt::DisplayRole});
    return true;
}

void ClipboardHistoryModel::expire()
{
    if (limits_.expiryMs < 0) return;
    const qint64 now = clock_();
    for (int i = entries_.size() - 1; i >= 0; --i) {
        if (!entries_.at(i).pinned && now - entries_.at(i).capturedAtMs >= limits_.expiryMs)
            removeRowSecure(i);
    }
}

void ClipboardHistoryModel::clear()
{
    if (entries_.isEmpty()) return;
    beginResetModel();
    for (Entry& entry : entries_) wipe(entry);
    entries_.clear();
    totalBytes_ = 0;
    endResetModel();
}

void ClipboardHistoryModel::removeRowSecure(int row)
{
    beginRemoveRows({}, row, row);
    totalBytes_ -= entries_[row].payloadBytes;
    wipe(entries_[row]);
    entries_.removeAt(row);
    endRemoveRows();
}

void ClipboardHistoryModel::wipe(Entry& entry)
{
    if (!entry.text.isEmpty()) {
        entry.text.detach();
        entry.text.fill(QChar(0));
        entry.text.clear();
        entry.text.squeeze();
    }
    if (!entry.imagePng.isEmpty()) {
        entry.imagePng.detach();
        entry.imagePng.fill(char(0));
        entry.imagePng.clear();
        entry.imagePng.squeeze();
    }
    entry.payloadBytes = 0;
    entry.imageSize = {};
    entry.capturedAtMs = 0;
}

const ClipboardHistoryModel::Entry* ClipboardHistoryModel::entry(int row) const
{
    return row >= 0 && row < entries_.size() ? &entries_.at(row) : nullptr;
}

int ClipboardHistoryModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : entries_.size();
}

QString ClipboardHistoryModel::preview(const Entry& entry) const
{
    if (entry.type == Type::Image)
        return tr("Imagem %1 × %2").arg(entry.imageSize.width()).arg(entry.imageSize.height());
    QString result = entry.text.left(160);
    for (QChar& c : result) if (c.category() == QChar::Other_Control) c = QLatin1Char(' ');
    return result.simplified();
}

QVariant ClipboardHistoryModel::data(const QModelIndex& modelIndex, int role) const
{
    const Entry* value = entry(modelIndex.row());
    if (!modelIndex.isValid() || !value) return {};
    switch (role) {
    case Qt::DisplayRole: return (value->pinned ? QStringLiteral("📌 ") : QString()) + preview(*value);
    case TypeRole: return int(value->type);
    case TimestampRole: return value->capturedAtMs;
    case PinnedRole: return value->pinned;
    case PayloadBytesRole: return value->payloadBytes;
    default: return {};
    }
}

QHash<int, QByteArray> ClipboardHistoryModel::roleNames() const
{
    return {{Qt::DisplayRole, "display"}, {TypeRole, "type"}, {TimestampRole, "timestamp"},
            {PinnedRole, "pinned"}, {PayloadBytesRole, "payloadBytes"}};
}
