#include "FileTransferResume.h"

#include <QCryptographicHash>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

namespace FileTransferResume {
namespace {
constexpr quint32 Magic=0x494c524d; // ILRM
constexpr quint16 Version=3;
constexpr int TagBytes=32;
constexpr qint64 MaxFutureSkewSeconds=5*60;
void fail(QString* error,const QString& text){if(error)*error=text;}
QByteArray mac(const QByteArray& key,const QByteArray& payload)
{
    if(key.size()!=32)return {};
    unsigned char result[EVP_MAX_MD_SIZE]; unsigned int size=0;
    if(!HMAC(EVP_sha256(),key.constData(),key.size(),reinterpret_cast<const unsigned char*>(payload.constData()),size_t(payload.size()),result,&size))return {};
    return QByteArray(reinterpret_cast<const char*>(result),int(size));
}
bool valid(const Manifest& m)
{
    return m.transferId.size()>=16&&m.transferId.size()<=32&&!m.peerUuid.isNull()&&m.itemIndex<10000&&
        isSafeRelativePath(m.relativePath)&&m.relativePath.toUtf8().size()<=MaxRelativePathUtf8&&m.expectedSize<=MaxFileBytes&&
        m.sha256.size()==32&&m.offset<=m.expectedSize&&((m.offset==0&&m.prefixSha256.isEmpty())||(m.offset>0&&m.prefixSha256.size()==32))&&
        m.updatedAtUtc.isValid()&&m.publishedPath.toUtf8().size()<=MaxRelativePathUtf8&&
        m.recoveryPath.toUtf8().size()<=MaxRelativePathUtf8&&
        (!m.completed||(!m.publishedPath.isEmpty()&&m.offset==m.expectedSize&&constantTimeEqual(m.prefixSha256,m.sha256)));
}
bool validTransferId(const QByteArray& id){return id.size()>=16&&id.size()<=32;}
}

bool isSafeRelativePath(const QString& path)
{
    if(path.isEmpty()||QDir::isAbsolutePath(path)||path.contains('\\')||path.contains(QChar::Null)||path.startsWith(".inputleap-part-"))return false;
    const QString clean=QDir::cleanPath(path);
    if(clean!=path||clean==".."||clean.startsWith("../")||clean.startsWith("./")||path.contains("//"))return false;
    for(const auto& component:path.split('/'))if(component.isEmpty()||component=="."||component=="..")return false;
    return true;
}

bool constantTimeEqual(const QByteArray& a,const QByteArray& b)
{
    return a.size()==b.size()&&!a.isEmpty()&&CRYPTO_memcmp(a.constData(),b.constData(),size_t(a.size()))==0;
}

QByteArray deriveContextKey(const QByteArray& sessionKey,const QByteArray& context)
{
    if(sessionKey.size()!=32||context.isEmpty()||context.size()>128)return {};
    const QByteArray prk=mac(QByteArray(32,'\0'),sessionKey);
    return mac(prk,QByteArray("inputleap/file-transfer/")+context+QByteArray(1,'\1'));
}

QByteArray scopedStorageId(const QUuid& authenticatedPeer,const QByteArray& transferId)
{
    if(authenticatedPeer.isNull()||transferId.size()<16||transferId.size()>32)return {};
    return QCryptographicHash::hash(QByteArray("inputleap-resume-storage-v1\0",28)+authenticatedPeer.toRfc4122()+transferId,
                                    QCryptographicHash::Sha256).left(16);
}

QByteArray encodeManifest(const Manifest& m,const QByteArray& contextKey,QString* error)
{
    if(contextKey.size()!=32){fail(error,"chave de contexto inválida");return {};}
    if(!valid(m)){fail(error,"manifesto de retomada inválido");return {};}
    QByteArray payload; QDataStream out(&payload,QIODevice::WriteOnly); out.setVersion(QDataStream::Qt_6_0); out.setByteOrder(QDataStream::BigEndian);
    out<<Magic<<Version<<m.transferId<<m.peerUuid<<m.itemIndex<<m.relativePath<<m.expectedSize
       <<m.sha256<<m.offset<<m.prefixSha256<<m.updatedAtUtc.toMSecsSinceEpoch()
       <<m.publishedPath<<m.recoveryPath<<m.completed;
    if(out.status()!=QDataStream::Ok||payload.size()>MaxManifestBytes-TagBytes){fail(error,"manifesto de retomada excede o limite");return {};}
    const QByteArray tag=mac(contextKey,payload); if(tag.size()!=TagBytes)return {};
    return payload+tag;
}

std::optional<Manifest> decodeManifest(const QByteArray& data,const QByteArray& contextKey,const QUuid& authenticatedPeer,QString* error)
{
    if(data.size()<=TagBytes||data.size()>MaxManifestBytes||contextKey.size()!=32||authenticatedPeer.isNull()){fail(error,"manifesto de retomada inválido");return std::nullopt;}
    const QByteArray payload=data.left(data.size()-TagBytes), supplied=data.right(TagBytes), expected=mac(contextKey,payload);
    if(!constantTimeEqual(supplied,expected)){fail(error,"autenticação do manifesto de retomada falhou");return std::nullopt;}
    Manifest m; quint32 magic=0; quint16 version=0; qint64 timestamp=0;
    QDataStream in(payload); in.setVersion(QDataStream::Qt_6_0); in.setByteOrder(QDataStream::BigEndian);
    in>>magic>>version>>m.transferId>>m.peerUuid>>m.itemIndex>>m.relativePath>>m.expectedSize
      >>m.sha256>>m.offset>>m.prefixSha256>>timestamp>>m.publishedPath>>m.recoveryPath>>m.completed;
    m.updatedAtUtc=QDateTime::fromMSecsSinceEpoch(timestamp,Qt::UTC);
    if(in.status()!=QDataStream::Ok||!in.atEnd()||magic!=Magic||version!=Version||!valid(m)||m.peerUuid!=authenticatedPeer){fail(error,"manifesto de retomada incompatível");return std::nullopt;}
    const qint64 age=m.updatedAtUtc.secsTo(QDateTime::currentDateTimeUtc());
    if(age>RetentionSeconds||age<-MaxFutureSkewSeconds){fail(error,"data do manifesto de retomada fora da janela permitida");return std::nullopt;}
    return m;
}

QString partPath(const QString& root,const QByteArray& id){return validTransferId(id)?QDir(root).filePath(".inputleap-part-"+QString::fromLatin1(id.toHex())):QString();}
QString manifestPath(const QString& root,const QByteArray& id){const QString part=partPath(root,id);return part.isEmpty()?QString():part+".manifest";}

quint64 verifiedOffset(const Manifest& m,const QString& path,QString* error)
{
    if(!valid(m)||m.offset==0)return 0;
    QFileInfo info(path); if(!info.exists()||!info.isFile()||info.isSymLink()||quint64(info.size())!=m.offset||quint64(info.size())>m.expectedSize){fail(error,"arquivo parcial não corresponde ao manifesto");return 0;}
    QFile file(path); if(!file.open(QIODevice::ReadOnly)){fail(error,"não foi possível validar o arquivo parcial");return 0;}
    QCryptographicHash hash(QCryptographicHash::Sha256); while(!file.atEnd()){const QByteArray chunk=file.read(64*1024);if(chunk.isEmpty()&&!file.atEnd())return 0;hash.addData(chunk);}
    if(!constantTimeEqual(hash.result(),m.prefixSha256)){fail(error,"hash do arquivo parcial não confere");return 0;}
    return m.offset;
}

bool saveManifestAtomic(const QString& path,const QByteArray& encoded,QString* error)
{
    if(encoded.isEmpty()||encoded.size()>MaxManifestBytes){fail(error,"manifesto de retomada inválido");return false;}
    QSaveFile file(path); file.setDirectWriteFallback(false); if(!file.open(QIODevice::WriteOnly)){fail(error,"não foi possível criar o manifesto de retomada");return false;}
    file.setPermissions(QFileDevice::ReadOwner|QFileDevice::WriteOwner);
    if(file.write(encoded)!=encoded.size()||!file.commit()){fail(error,"não foi possível salvar o manifesto de retomada");return false;} return true;
}
}
