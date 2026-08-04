#include "TransferQueue.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QRegularExpression>
#include <cmath>

namespace {
constexpr int kVersion=3;
constexpr qsizetype kMaxStoreBytes=1024*1024;
constexpr int kMaxItems=200;
constexpr int kMaxTextBytes=4096;

bool exactKeys(const QJsonObject& object,const QSet<QString>& expected)
{
    QSet<QString> actual;
    for(auto it=object.begin();it!=object.end();++it)actual.insert(it.key());
    return actual==expected;
}

bool safeRelative(const QString& path)
{
    if(path.isEmpty()||path.toUtf8().size()>kMaxTextBytes||QDir::isAbsolutePath(path)||path.contains('\\')||path.contains(QChar::Null))return false;
    const QString clean=QDir::cleanPath(path);
    return clean==path&&clean!=".."&&!clean.startsWith("../")&&!clean.startsWith("./")&&!path.contains("//");
}

void setError(QString* error,const QString& value){if(error)*error=value;}
}

TransferQueue::TransferQueue(QString storePath):storePath_(QFileInfo(std::move(storePath)).absoluteFilePath()){}

QByteArray TransferQueue::newTransferId(){return QUuid::createUuid().toRfc4122();}

QString TransferQueue::stateName(State state)
{
    switch(state){
    case State::Pending:return "pending"; case State::Running:return "running"; case State::Paused:return "paused";
    case State::Completed:return "completed"; case State::FailedRetryable:return "failed-retryable";
    case State::FailedTerminal:return "failed-terminal"; case State::Cancelled:return "cancelled"; case State::Skipped:return "skipped";
    }
    return {};
}

std::optional<TransferQueue::State> TransferQueue::parseState(const QString& value)
{
    for(State state:{State::Pending,State::Running,State::Paused,State::Completed,State::FailedRetryable,State::FailedTerminal,State::Cancelled,State::Skipped})
        if(stateName(state)==value)return state;
    return std::nullopt;
}

bool TransferQueue::validItem(const Item& item,QString* error)
{
    if(item.transferId.size()!=16||(!item.batchId.isEmpty()&&item.batchId.size()!=16)||item.batchCount==0||item.batchCount>quint32(kMaxItems)||item.batchIndex>=item.batchCount||
       item.peerUuid.isNull()||item.displayName.isEmpty()||item.displayName.toUtf8().size()>256||
       item.sources.size()!=1||!item.createdAtUtc.isValid()||!item.updatedAtUtc.isValid()||
       item.attempts<0||item.attempts>1000){setError(error,"item inválido na fila");return false;}
    for(const auto& source:item.sources){
        if(source.sourcePath.isEmpty()||source.sourcePath.toUtf8().size()>kMaxTextBytes||!QDir::isAbsolutePath(source.sourcePath)||
           !safeRelative(source.relativePath)){setError(error,"origem inválida na fila");return false;}
    }
    return true;
}

std::optional<TransferQueue::Item> TransferQueue::find(const QByteArray& id) const
{for(const auto& value:items_)if(value.transferId==id)return value;return std::nullopt;}
TransferQueue::Item* TransferQueue::mutableItem(const QByteArray& id)
{for(auto& value:items_)if(value.transferId==id)return &value;return nullptr;}

bool TransferQueue::enqueue(const Item& item,QString* error)
{
    if(items_.size()>=kMaxItems||find(item.transferId)||!validItem(item,error)){if(error&&error->isEmpty())setError(error,"fila cheia ou item duplicado");return false;}
    items_.append(item);
    if (!save(error)) { items_.removeLast(); return false; }
    return true;
}

bool TransferQueue::enqueueMany(const QList<Item>& values,QString* error)
{
    if(values.isEmpty()||items_.size()+values.size()>kMaxItems){setError(error,"fila cheia ou lote vazio");return false;}
    QSet<QByteArray> ids;for(const auto& existing:items_)ids.insert(existing.transferId);
    for(const auto& value:values){if(ids.contains(value.transferId)||!validItem(value,error)){if(error&&error->isEmpty())setError(error,"item duplicado no lote");return false;}ids.insert(value.transferId);}
    const qsizetype oldSize=items_.size();items_.append(values);
    if(!save(error)){while(items_.size()>oldSize)items_.removeLast();return false;}return true;
}

bool TransferQueue::persistMutation(QString* error){return save(error);}

bool TransferQueue::pause(const QByteArray& id,QString* error)
{
    Item* value=mutableItem(id);if(!value||(value->state!=State::Running&&value->state!=State::Pending&&value->state!=State::FailedRetryable)){setError(error,"item não pode ser pausado");return false;}
    const Item old=*value;value->state=State::Paused;value->updatedAtUtc=QDateTime::currentDateTimeUtc();if(!persistMutation(error)){*value=old;return false;}return true;
}

bool TransferQueue::continueItem(const QByteArray& id,QString* error)
{
    Item* value=mutableItem(id);if(!value||value->state!=State::Paused){setError(error,"item não está pausado");return false;}
    const Item old=*value;value->state=State::Pending;value->updatedAtUtc=QDateTime::currentDateTimeUtc();if(!persistMutation(error)){*value=old;return false;}return true;
}

bool TransferQueue::cancel(const QByteArray& id,QString* error)
{
    Item* value=mutableItem(id);if(!value||value->state==State::Completed||value->state==State::Cancelled||value->state==State::Skipped){setError(error,"item não pode ser cancelado");return false;}
    const Item old=*value;value->state=State::Cancelled;value->userEnqueued=false;value->updatedAtUtc=QDateTime::currentDateTimeUtc();if(!persistMutation(error)){*value=old;return false;}return true;
}

std::optional<QByteArray> TransferQueue::repeat(const QByteArray& id,QString* error)
{
    const auto original=find(id);if(!original||(original->state!=State::FailedTerminal&&original->state!=State::FailedRetryable&&original->state!=State::Cancelled&&original->state!=State::Skipped)){setError(error,"item não pode ser repetido");return std::nullopt;}
    Item copy=*original;copy.transferId=newTransferId();copy.batchId=QUuid::createUuid().toRfc4122();copy.batchIndex=0;copy.batchCount=1;copy.state=State::Pending;copy.userEnqueued=true;copy.confirmedBytes=0;copy.attempts=0;copy.generation=0;copy.createdAtUtc=copy.updatedAtUtc=QDateTime::currentDateTimeUtc();
    if(!enqueue(copy,error))return std::nullopt;return copy.transferId;
}

bool TransferQueue::markRunning(const QByteArray& id,quint64* generation,QString* error)
{
    Item* value=mutableItem(id);if(!value||!value->userEnqueued||(value->state!=State::Pending&&value->state!=State::FailedRetryable)){setError(error,"item não está pronto");return false;}
    const Item old=*value;value->state=State::Running;++value->generation;++value->attempts;value->updatedAtUtc=QDateTime::currentDateTimeUtc();if(!save(error)){*value=old;return false;}if(generation)*generation=value->generation;return true;
}

bool TransferQueue::finish(const QByteArray& id,quint64 generation,State result,QString* error)
{
    if(result!=State::Completed&&result!=State::FailedRetryable&&result!=State::FailedTerminal&&result!=State::Paused&&result!=State::Cancelled&&result!=State::Skipped){setError(error,"resultado inválido");return false;}
    Item* value=mutableItem(id);if(!value||value->state!=State::Running||value->generation!=generation){setError(error,"retorno antigo ignorado");return false;}
    const Item old=*value;value->state=result;if(result==State::Cancelled||result==State::Skipped)value->userEnqueued=false;value->updatedAtUtc=QDateTime::currentDateTimeUtc();if(!save(error)){*value=old;return false;}return true;
}

std::optional<TransferQueue::Item> TransferQueue::nextEligible(const std::function<bool(const Item&)>& eligible) const
{
    for (const auto& value : items_) if (value.state == State::Running) return std::nullopt;
    for(const auto& value:items_)if(value.userEnqueued&&(value.state==State::Pending||value.state==State::FailedRetryable)&&eligible(value))return value;
    return std::nullopt;
}

std::optional<TransferQueue::Item> TransferQueue::nextEligibleConcurrent(const std::function<bool(const Item&)>& eligible) const
{
    for(const auto& value:items_)if(value.userEnqueued&&(value.state==State::Pending||value.state==State::FailedRetryable)&&eligible(value))return value;
    return std::nullopt;
}

bool TransferQueue::save(QString* error) const
{
    if (!persistenceEnabled_) {
        setError(error, "persistência da fila desabilitada");
        return false;
    }
    QJsonArray array;
    for(const auto& item:items_){
        if(!validItem(item,error))return false;
        QJsonArray sources;for(const auto& source:item.sources)sources.append(QJsonObject{{"sourcePath",source.sourcePath},{"relativePath",source.relativePath}});
        const QByteArray batchId=item.batchId.size()==16?item.batchId:item.transferId;
        array.append(QJsonObject{{"transferId",QString::fromLatin1(item.transferId.toHex())},{"batchId",QString::fromLatin1(batchId.toHex())},
            {"batchIndex",double(item.batchIndex)},{"batchCount",double(item.batchCount)},{"peerUuid",item.peerUuid.toString(QUuid::WithoutBraces)},
            {"displayName",item.displayName},{"sources",sources},{"state",stateName(item.state)},{"userEnqueued",item.userEnqueued},
            {"confirmedBytes",double(item.confirmedBytes)},{"attempts",item.attempts},{"generation",double(item.generation)},
            {"createdAt",double(item.createdAtUtc.toMSecsSinceEpoch())},{"updatedAt",double(item.updatedAtUtc.toMSecsSinceEpoch())}});
    }
    const QByteArray bytes=QJsonDocument(QJsonObject{{"version",kVersion},{"items",array}}).toJson(QJsonDocument::Compact);
    if(bytes.size()>kMaxStoreBytes){setError(error,"fila excede o limite");return false;}
    QDir().mkpath(QFileInfo(storePath_).absolutePath());QSaveFile file(storePath_);
    if(!file.open(QIODevice::WriteOnly)||file.write(bytes)!=bytes.size()||!file.commit()){setError(error,"não foi possível salvar a fila");return false;}
    QFile::setPermissions(storePath_,QFileDevice::ReadOwner|QFileDevice::WriteOwner);return true;
}

TransferQueue::LoadResult TransferQueue::load(QString* error)
{
    QFile file(storePath_);
    if (!file.exists()) return LoadResult::Missing;
    auto corrupt = [&](const QString& reason) {
        setError(error, reason);
        file.close();
        QString quarantine = storePath_ + QStringLiteral(".corrupt-") +
            QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMddTHHmmsszzzZ"));
        if (QFile::exists(quarantine)) quarantine += QStringLiteral("-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (!QFile::rename(storePath_, quarantine) && error) *error += QStringLiteral("; não foi possível isolar o arquivo");
        items_.clear();
        return LoadResult::Corrupt;
    };
    if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxStoreBytes) return corrupt(QStringLiteral("fila inválida"));
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) return corrupt(QStringLiteral("fila corrompida"));
    const QJsonObject root = document.object();
    if (!exactKeys(root,{"version","items"}) || !root.value("version").isDouble() || !root.value("items").isArray())
        return corrupt(QStringLiteral("formato da fila inválido"));
    const double storeVersion=root.value("version").toDouble();
    if(storeVersion!=1.0&&storeVersion!=2.0&&storeVersion!=double(kVersion)){setError(error,"versão da fila não suportada");return LoadResult::Unsupported;}
    const QJsonArray array = root.value("items").toArray();
    if (array.size() > kMaxItems) return corrupt(QStringLiteral("fila excede o limite"));
    QList<Item> loaded;QSet<QByteArray> loadedIds;
    bool normalizedRunning = false;
    const QSet<QString> legacyItemKeys={"transferId","peerUuid","displayName","sources","state","userEnqueued","confirmedBytes","attempts","generation","createdAt","updatedAt"};
    QSet<QString> itemKeys=legacyItemKeys;if(storeVersion>=3.0)itemKeys.unite({"batchId","batchIndex","batchCount"});
    for (const auto& entry : array) {
        if (!entry.isObject() || !exactKeys(entry.toObject(),itemKeys)) return corrupt(QStringLiteral("item desconhecido na fila"));
        const auto object=entry.toObject();
        if (!object.value("transferId").isString() || !object.value("peerUuid").isString() || !object.value("displayName").isString() || !object.value("sources").isArray() ||
            !object.value("state").isString() || !object.value("userEnqueued").isBool() || !object.value("confirmedBytes").isDouble() ||
            !object.value("attempts").isDouble() || !object.value("generation").isDouble() || !object.value("createdAt").isDouble() || !object.value("updatedAt").isDouble())
            return corrupt(QStringLiteral("tipos inválidos na fila"));
        for(const auto& key:{"confirmedBytes","attempts","generation","createdAt","updatedAt"}){const double number=object.value(key).toDouble();if(!std::isfinite(number)||number<0||number>9007199254740991.0||std::floor(number)!=number)return corrupt(QStringLiteral("número inválido na fila"));}
        Item item;const QString encodedId=object.value("transferId").toString();
        if(!QRegularExpression(QStringLiteral("^[0-9a-f]{32}$")).match(encodedId).hasMatch())return corrupt(QStringLiteral("identificador não canônico na fila"));
        item.transferId=QByteArray::fromHex(encodedId.toLatin1());if(loadedIds.contains(item.transferId))return corrupt(QStringLiteral("identificador duplicado na fila"));loadedIds.insert(item.transferId);
        if(storeVersion>=3.0){
            if(!object.value("batchId").isString()||!object.value("batchIndex").isDouble()||!object.value("batchCount").isDouble())return corrupt(QStringLiteral("lote inválido na fila"));
            const QString encodedBatch=object.value("batchId").toString();if(!QRegularExpression(QStringLiteral("^[0-9a-f]{32}$")).match(encodedBatch).hasMatch())return corrupt(QStringLiteral("lote não canônico na fila"));
            item.batchId=QByteArray::fromHex(encodedBatch.toLatin1());const double index=object.value("batchIndex").toDouble(-1),count=object.value("batchCount").toDouble(-1);
            if(!std::isfinite(index)||!std::isfinite(count)||index<0||count<1||count>kMaxItems||std::floor(index)!=index||std::floor(count)!=count||index>=count)return corrupt(QStringLiteral("posição de lote inválida na fila"));
            item.batchIndex=quint32(index);item.batchCount=quint32(count);
        }else{item.batchId=item.transferId;item.batchIndex=0;item.batchCount=1;}
        item.peerUuid=QUuid(object.value("peerUuid").toString());
        item.displayName=object.value("displayName").toString();
        const auto state=parseState(object.value("state").toString());
        if (!state) return corrupt(QStringLiteral("estado inválido na fila"));
        item.state=*state;
        item.userEnqueued=object.value("userEnqueued").toBool();
        item.confirmedBytes=quint64(object.value("confirmedBytes").toDouble(-1));
        item.attempts=object.value("attempts").toInt(-1);
        item.generation=quint64(object.value("generation").toDouble(-1));
        item.createdAtUtc=QDateTime::fromMSecsSinceEpoch(qint64(object.value("createdAt").toDouble()),Qt::UTC);
        item.updatedAtUtc=QDateTime::fromMSecsSinceEpoch(qint64(object.value("updatedAt").toDouble()),Qt::UTC);
        const auto sources=object.value("sources").toArray();
        if (sources.size()!=1) return corrupt(QStringLiteral("cada item deve conter exatamente uma origem"));
        for (const auto& sourceValue:sources) {
            if (!sourceValue.isObject() || !exactKeys(sourceValue.toObject(),{"sourcePath","relativePath"})) return corrupt(QStringLiteral("origem inválida na fila"));
            const auto source=sourceValue.toObject();if(!source.value("sourcePath").isString()||!source.value("relativePath").isString())return corrupt(QStringLiteral("origem inválida na fila"));
            item.sources.append({source.value("sourcePath").toString(),source.value("relativePath").toString()});
        }
        if (item.state==State::Running) {
            item.state=item.userEnqueued?State::Pending:State::Paused;
            item.updatedAtUtc=QDateTime::currentDateTimeUtc();
            normalizedRunning = true;
        }
        if (!validItem(item,error)) return corrupt(error ? *error : QStringLiteral("item inválido na fila"));
        loaded.append(item);
    }
    items_=loaded;
    file.close();
    if (normalizedRunning && !save(error)) return corrupt(QStringLiteral("não foi possível persistir a recuperação segura da fila"));
    return LoadResult::Loaded;
}
