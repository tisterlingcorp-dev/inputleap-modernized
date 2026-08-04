#include "DeviceCardDropPolicy.h"
#include "FileTransferService.h"
#include <QFileInfo>
#include <QMimeData>
#include <QUrl>

DeviceCardDropPolicy::Result DeviceCardDropPolicy::evaluate(const QMimeData* mimeData)
{
    Result result;
    if (!mimeData || !mimeData->hasUrls()) { result.reason=QObject::tr("Arraste arquivos ou pastas locais."); return result; }
    const QList<QUrl> urls=mimeData->urls();
    if (urls.isEmpty() || urls.size()>MaximumItems) { result.reason=QObject::tr("Selecione de 1 a %1 itens.").arg(MaximumItems); return result; }
    for (const QUrl& url:urls) {
        if (!url.isValid() || !url.isLocalFile() || url.scheme().compare("file",Qt::CaseInsensitive)!=0) { result.reason=QObject::tr("Somente arquivos locais são aceitos."); return result; }
        const QString path=url.toLocalFile(); const QFileInfo info(path);
        if (path.trimmed().isEmpty() || !info.exists() || info.isSymLink() || (!info.isFile()&&!info.isDir()) || !info.isReadable()) { result.reason=QObject::tr("Um item não existe, é um link ou não pode ser lido."); return result; }
        result.paths.append(info.absoluteFilePath());
        if (info.isDir()) result.confirmation=Confirmation::Directory;
        else if (result.confirmation==Confirmation::None && !FileTransferService::isSafeToOpenAutomatically(info.fileName())) result.confirmation=Confirmation::Dangerous;
    }
    result.accepted=true; return result;
}
