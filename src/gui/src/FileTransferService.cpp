/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "FileTransferService.h"
#include "FileTransferResume.h"
#include "TransferPerformance.h"

#include <QDataStream>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <QScopeGuard>
#include <QCryptographicHash>
#include <QDateTime>
#include <QStandardPaths>
#include <QPointer>
#include <QThreadPool>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslPreSharedKeyAuthenticator>
#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <openssl/crypto.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>
#include <atomic>
#include <memory>
#include <vector>
#ifdef Q_OS_WIN
#include <windows.h>
#include <winternl.h>
#include <io.h>
#include <fcntl.h>
#else
#include <sys/file.h>
#include <sys/stat.h>
#endif

namespace
{
const int kConnectTimeoutMs = 8000;
const int kWriteTimeoutMs = 30000;
const int kHeaderResponseTimeoutMs = 120000;
const int kChunkSize = 64 * 1024;
const quint32 kMagic = 0x494c4654; // ILFT
const quint16 kProtocolVersion = 5;
const quint64 kProgressStepBytes = 1024 * 1024;
const char kTransferAccepted = 1;
const char kTransferRejected = 2;
const char kTransferAlreadyComplete = 3;
const char kTransferDeduplicated = 4;
const char kTransferSkipped = 5;
const QByteArray kLegacyTlsPskIdentity("inputleap-file-transfer");
const QByteArray kDeviceIdentityPrefix("inputleap-file-transfer:");

enum class SocketWaitResult { Ready, Failed, Cancelled };

template <class Ready, class Wait, class Cancel>
SocketWaitResult waitForSocketCancellable(QAbstractSocket& socket, int timeoutMs,
                                          Ready ready, Wait wait, Cancel cancel)
{
    QElapsedTimer timer;
    timer.start();
    while (!ready()) {
        if (cancel && cancel()) {
            socket.abort();
            return SocketWaitResult::Cancelled;
        }
        if (socket.state() == QAbstractSocket::UnconnectedState)
            return SocketWaitResult::Failed;
        const int remaining = timeoutMs - int(timer.elapsed());
        if (remaining <= 0) return SocketWaitResult::Failed;
        wait((std::min)(remaining, 50));
    }
    return SocketWaitResult::Ready;
}

bool isDirectCanonicalPath(const QString& path)
{
    const QFileInfo info(path);
    const QString absolute=QDir::cleanPath(info.absoluteFilePath());
    const QString canonical=QDir::cleanPath(info.canonicalFilePath());
    if(canonical.isEmpty())return false;
#ifdef Q_OS_WIN
    return absolute.compare(canonical,Qt::CaseInsensitive)==0;
#else
    return absolute==canonical;
#endif
}

bool openedFileStillMatchesPath(QFile& file,const QString& path)
{
    if(!isDirectCanonicalPath(path))return false;
#ifdef Q_OS_WIN
    const intptr_t native=_get_osfhandle(file.handle());
    if(native==-1)return false;
    BY_HANDLE_FILE_INFORMATION opened{};
    if(!GetFileInformationByHandle(reinterpret_cast<HANDLE>(native),&opened))return false;
    const QString nativePath=QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    HANDLE current=CreateFileW(reinterpret_cast<LPCWSTR>(nativePath.utf16()),GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(current==INVALID_HANDLE_VALUE)return false;
    BY_HANDLE_FILE_INFORMATION now{};const bool queried=GetFileInformationByHandle(current,&now);CloseHandle(current);
    return queried && !(now.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
        opened.dwVolumeSerialNumber==now.dwVolumeSerialNumber && opened.nFileIndexHigh==now.nFileIndexHigh && opened.nFileIndexLow==now.nFileIndexLow;
#else
    struct stat opened{},current{};
    return ::fstat(file.handle(),&opened)==0 && ::stat(QFile::encodeName(path).constData(),&current)==0 &&
        opened.st_dev==current.st_dev && opened.st_ino==current.st_ino;
#endif
}

struct FileIdentity
{
    quint64 first=0,second=0,size=0,version=0; bool valid=false;
    bool operator==(const FileIdentity&) const = default;
};

FileIdentity identityForOpenFile(QFile& file)
{
#ifdef Q_OS_WIN
    const intptr_t native=_get_osfhandle(file.handle()); BY_HANDLE_FILE_INFORMATION info{};
    if(native==-1||!GetFileInformationByHandle(reinterpret_cast<HANDLE>(native),&info)||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)))return {};
    const quint64 size=(quint64(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    const quint64 version=(quint64(info.ftLastWriteTime.dwHighDateTime)<<32)|info.ftLastWriteTime.dwLowDateTime;
    return {info.dwVolumeSerialNumber,(quint64(info.nFileIndexHigh)<<32)|info.nFileIndexLow,size,version,true};
#else
    struct stat info{};if(::fstat(file.handle(),&info)!=0||!S_ISREG(info.st_mode))return {};
    const quint64 version=(quint64(info.st_ctim.tv_sec)*1000000000ULL)+quint64(info.st_ctim.tv_nsec);
    return {quint64(info.st_dev),quint64(info.st_ino),quint64(info.st_size),version,true};
#endif
}

FileIdentity identityForDirectPath(const QString& path)
{
    QFile file(path);if(!file.open(QIODevice::ReadOnly)||!openedFileStillMatchesPath(file,path))return {};
    return identityForOpenFile(file);
}

#ifdef Q_OS_WIN
constexpr ULONG kNtFileOpen=1;
constexpr ULONG kNtFileCreate=2;
constexpr ULONG kNtFileDirectory=0x00000001;
constexpr ULONG kNtFileSynchronousNonAlert=0x00000020;
constexpr ULONG kNtFileNonDirectory=0x00000040;
constexpr ULONG kNtFileOpenReparsePoint=0x00200000;
HANDLE openRelativeToDirectory(HANDLE directoryHandle,const QString& leaf,ACCESS_MASK access,
                               ULONG shareMode,ULONG disposition,ULONG options);
bool windowsHandleMatchesPath(HANDLE handle,const QString& expected);
QString volumeRootForPath(const QString& path)
{
    QString probe=QFileInfo(path).absoluteFilePath();
    while(!QFileInfo::exists(probe)){
        const QString parent=QFileInfo(probe).absolutePath();
        if(parent==probe)return {};
        probe=parent;
    }
    const QString native=QDir::toNativeSeparators(probe);
    std::vector<wchar_t> buffer(32768);
    if(!GetVolumePathNameW(reinterpret_cast<LPCWSTR>(native.utf16()),buffer.data(),
                           DWORD(buffer.size())))return {};
    return QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(buffer.data())));
}
#endif

bool ensureSecureDirectory(const QString& directory
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                           ,const FileTransferService::AtomicPublishTestHooks* testHooks = nullptr
#endif
                           )
{
    const QString absolute=QDir::cleanPath(QFileInfo(directory).absoluteFilePath());
    const QString root=
#ifdef Q_OS_WIN
        volumeRootForPath(absolute);
#else
        QDir::rootPath();
#endif
    if(root.isEmpty())return false;
    QString current=QDir::cleanPath(root);
    const QString relative=QDir(root).relativeFilePath(absolute);
#ifdef Q_OS_WIN
    std::vector<HANDLE> handles;
    std::vector<HANDLE> writableHandles;
    const auto closeHandles=qScopeGuard([&]{
        for(const HANDLE handle:handles)if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);
        for(const HANDLE handle:writableHandles)if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);
    });
    const QString nativeRoot=QDir::toNativeSeparators(current);
    HANDLE rootHandle=CreateFileW(reinterpret_cast<LPCWSTR>(nativeRoot.utf16()),
        FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(rootHandle==INVALID_HANDLE_VALUE)return false;
    handles.push_back(rootHandle);
    BY_HANDLE_FILE_INFORMATION rootInfo{};
    if(!GetFileInformationByHandle(rootHandle,&rootInfo)||
       !(rootInfo.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
       (rootInfo.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))return false;
    HANDLE writableRoot=CreateFileW(reinterpret_cast<LPCWSTR>(nativeRoot.utf16()),
        FILE_ADD_SUBDIRECTORY|FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    writableHandles.push_back(writableRoot);
    for(const QString& component:relative.split('/',Qt::SkipEmptyParts)){
        if(component==QStringLiteral("."))continue;
        current=QDir(current).filePath(component);
        HANDLE handle=openRelativeToDirectory(handles.back(),component,
            FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,
            kNtFileOpen,kNtFileDirectory|kNtFileSynchronousNonAlert|kNtFileOpenReparsePoint);
        HANDLE writableHandle=INVALID_HANDLE_VALUE;
        if(handle==INVALID_HANDLE_VALUE){
            const HANDLE writableParent=writableHandles.back();
            if(writableParent==INVALID_HANDLE_VALUE)return false;
            handle=openRelativeToDirectory(writableParent,component,
                FILE_ADD_SUBDIRECTORY|FILE_LIST_DIRECTORY|FILE_TRAVERSE|
                FILE_READ_ATTRIBUTES|SYNCHRONIZE,
                FILE_SHARE_READ|FILE_SHARE_WRITE,
                kNtFileCreate,kNtFileDirectory|kNtFileSynchronousNonAlert|kNtFileOpenReparsePoint);
            if(handle!=INVALID_HANDLE_VALUE&&!DuplicateHandle(GetCurrentProcess(),handle,
                GetCurrentProcess(),&writableHandle,0,FALSE,DUPLICATE_SAME_ACCESS))
                writableHandle=INVALID_HANDLE_VALUE;
        }
        else {
            writableHandle=openRelativeToDirectory(handles.back(),component,
                FILE_ADD_SUBDIRECTORY|FILE_LIST_DIRECTORY|FILE_TRAVERSE|
                FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,kNtFileOpen,
                kNtFileDirectory|kNtFileSynchronousNonAlert|kNtFileOpenReparsePoint);
        }
        if(handle==INVALID_HANDLE_VALUE)return false;
        handles.push_back(handle);
        writableHandles.push_back(writableHandle);
        BY_HANDLE_FILE_INFORMATION opened{};
        if(!GetFileInformationByHandle(handle,&opened)||
           !(opened.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
           (opened.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
           !windowsHandleMatchesPath(handle,current))return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        if(testHooks!=nullptr&&testHooks->phase)
            testHooks->phase(FileTransferService::AtomicPublishPhase::DirectoryComponentPinned,current);
#endif
    }
    return windowsHandleMatchesPath(handles.back(),absolute);
#else
    for(const QString& component:relative.split('/',Qt::SkipEmptyParts)){
        if(component==".")continue;current=QDir(current).filePath(component);QFileInfo info(current);
        if(!info.exists()&&!QDir().mkdir(current))return false;
        struct stat opened{};if(::lstat(QFile::encodeName(current).constData(),&opened)!=0||!S_ISDIR(opened.st_mode)||S_ISLNK(opened.st_mode))return false;
        if(!isDirectCanonicalPath(current))return false;
    }
    return isDirectCanonicalPath(absolute);
#endif
}

struct HashResult{QByteArray digest;FileIdentity identity;quint64 size=0;bool ok=false;bool deleteAccess=false;std::shared_ptr<QFile> lock;};
HashResult hashDirectFile(const QString& path,const std::shared_ptr<std::atomic_bool>& cancelled)
{
    auto file=std::make_shared<QFile>(path);
#ifdef Q_OS_WIN
    const QString native=QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    bool deleteAccess=true;
    HANDLE handle=CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),GENERIC_READ|DELETE|FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(handle==INVALID_HANDLE_VALUE){
        deleteAccess=false;
        handle=CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    }
    if(handle==INVALID_HANDLE_VALUE)return {};
    const int fd=_open_osfhandle(reinterpret_cast<intptr_t>(handle),_O_BINARY|_O_RDONLY|_O_NOINHERIT);
    if(fd<0){CloseHandle(handle);return {};}
    if(!file->open(fd,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)){_close(fd);return {};}
#else
    const bool deleteAccess=false;
    if(!file->open(QIODevice::ReadOnly)||::flock(file->handle(),LOCK_SH|LOCK_NB)!=0)return {};
#endif
    if(!openedFileStillMatchesPath(*file,path))return {};
    const FileIdentity before=identityForOpenFile(*file);const qint64 size=file->size();QCryptographicHash hash(QCryptographicHash::Sha256);
    while(!file->atEnd()){
        if(cancelled->load())return {};const QByteArray chunk=file->read(kChunkSize);
        if(chunk.isEmpty()&&!file->atEnd())return {};hash.addData(chunk);
    }
    if(file->size()!=size||!openedFileStillMatchesPath(*file,path)||identityForOpenFile(*file)!=before)return {};
    return {hash.result(),before,quint64(size),true,deleteAccess,std::move(file)};
}

struct PinnedDirectoryChain
{
#ifdef Q_OS_WIN
    std::vector<HANDLE> handles;
    ~PinnedDirectoryChain(){for(const HANDLE handle:handles)if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
#endif
};

#ifdef Q_OS_WIN
QString normalizedWindowsPath(QString path)
{
    path=QDir::toNativeSeparators(QDir::cleanPath(path));
    if(path.startsWith(QStringLiteral("\\\\?\\UNC\\"),Qt::CaseInsensitive))
        path=QStringLiteral("\\\\")+path.mid(8);
    else if(path.startsWith(QStringLiteral("\\\\?\\"),Qt::CaseInsensitive))
        path=path.mid(4);
    while(path.size()>3&&path.endsWith('\\'))path.chop(1);
    return path;
}

bool windowsHandleMatchesPath(HANDLE handle,const QString& expected)
{
    const DWORD required=GetFinalPathNameByHandleW(handle,nullptr,0,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(required==0)return false;
    std::vector<wchar_t> buffer(size_t(required)+1);
    const DWORD written=GetFinalPathNameByHandleW(handle,buffer.data(),DWORD(buffer.size()),
        FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    return written>0&&written<buffer.size()&&
        normalizedWindowsPath(QString::fromWCharArray(buffer.data(),int(written))).compare(
            normalizedWindowsPath(QFileInfo(expected).absoluteFilePath()),Qt::CaseInsensitive)==0;
}

HANDLE openRelativeToDirectory(HANDLE directoryHandle,const QString& leaf,ACCESS_MASK access,
                               ULONG shareMode,ULONG disposition,ULONG options)
{
    if(directoryHandle==INVALID_HANDLE_VALUE||leaf.isEmpty()||leaf==QStringLiteral(".")||
       leaf==QStringLiteral("..")||leaf.contains('/')||leaf.contains('\\'))return INVALID_HANDLE_VALUE;
    using NtCreateFileFn=NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,
        PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
    using RtlNtStatusToDosErrorFn=ULONG(NTAPI*)(NTSTATUS);
    const HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    const auto ntCreateFile=ntdll?reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(ntdll,"NtCreateFile")):nullptr;
    const auto rtlNtStatusToDosError=ntdll?reinterpret_cast<RtlNtStatusToDosErrorFn>(
        GetProcAddress(ntdll,"RtlNtStatusToDosError")):nullptr;
    if(!ntCreateFile||!rtlNtStatusToDosError){SetLastError(ERROR_PROC_NOT_FOUND);return INVALID_HANDLE_VALUE;}
    std::wstring nativeLeaf=leaf.toStdWString();
    UNICODE_STRING name{};
    name.Length=USHORT(nativeLeaf.size()*sizeof(wchar_t));
    name.MaximumLength=name.Length;
    name.Buffer=nativeLeaf.data();
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length=sizeof(attributes);
    attributes.RootDirectory=directoryHandle;
    attributes.ObjectName=&name;
    attributes.Attributes=OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK ioStatus{};
    HANDLE handle=INVALID_HANDLE_VALUE;
    const NTSTATUS status=ntCreateFile(&handle,access,&attributes,&ioStatus,nullptr,
        FILE_ATTRIBUTE_NORMAL,shareMode,disposition,options,nullptr,0);
    if(status<0){SetLastError(rtlNtStatusToDosError(status));return INVALID_HANDLE_VALUE;}
    return handle;
}

std::shared_ptr<PinnedDirectoryChain> pinParentChain(const QString& filePath)
{
    const QString parentPath=QFileInfo(filePath).absolutePath();
    const QString rootPath=volumeRootForPath(parentPath);
    if(rootPath.isEmpty())return {};
    QString current=QDir::cleanPath(rootPath);
    QStringList paths{current};
    for(const QString& component:QDir(rootPath).relativeFilePath(parentPath).split('/',Qt::SkipEmptyParts)){
        if(component!=QStringLiteral(".")){current=QDir(current).filePath(component);paths.push_back(QDir::cleanPath(current));}
    }
    auto chain=std::make_shared<PinnedDirectoryChain>();
    chain->handles.reserve(size_t(paths.size()));
    for(int index=0;index<paths.size();++index){
        HANDLE handle=INVALID_HANDLE_VALUE;
        if(index==0){
            const QString native=QDir::toNativeSeparators(paths.at(index));
            handle=CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),
                FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        }
        else {
            handle=openRelativeToDirectory(chain->handles.back(),QFileInfo(paths.at(index)).fileName(),
                FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                kNtFileOpen,kNtFileDirectory|kNtFileSynchronousNonAlert|kNtFileOpenReparsePoint);
        }
        if(handle==INVALID_HANDLE_VALUE)return {};
        chain->handles.push_back(handle);
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(handle,&info)||!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
           (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
           !windowsHandleMatchesPath(handle,paths.at(index)))return {};
    }
    return chain;
}

std::shared_ptr<PinnedDirectoryChain> pinDescendantParentChain(
    const QString& filePath,const QString& trustedRootPath,
    const std::shared_ptr<PinnedDirectoryChain>& trustedRootChain)
{
    if(!trustedRootChain||trustedRootChain->handles.empty()||
       !windowsHandleMatchesPath(trustedRootChain->handles.back(),trustedRootPath))return {};
    const QString parentPath=QFileInfo(filePath).absolutePath();
    const QString relative=QDir(trustedRootPath).relativeFilePath(parentPath);
    if(QDir::isAbsolutePath(relative)||relative==QStringLiteral("..")||
       relative.startsWith(QStringLiteral("../")))return {};
    auto chain=std::make_shared<PinnedDirectoryChain>();
    chain->handles.reserve(trustedRootChain->handles.size()+size_t(relative.count('/')+1));
    for(const HANDLE trusted:trustedRootChain->handles){
        HANDLE duplicate=INVALID_HANDLE_VALUE;
        if(!DuplicateHandle(GetCurrentProcess(),trusted,GetCurrentProcess(),&duplicate,
                            0,FALSE,DUPLICATE_SAME_ACCESS))return {};
        chain->handles.push_back(duplicate);
    }
    QString current=QDir::cleanPath(trustedRootPath);
    for(const QString& component:relative.split('/',Qt::SkipEmptyParts)){
        if(component==QStringLiteral("."))continue;
        current=QDir(current).filePath(component);
        const HANDLE handle=openRelativeToDirectory(chain->handles.back(),component,
            FILE_LIST_DIRECTORY|FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,kNtFileOpen,
            kNtFileDirectory|kNtFileSynchronousNonAlert|kNtFileOpenReparsePoint);
        if(handle==INVALID_HANDLE_VALUE)return {};
        chain->handles.push_back(handle);
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(handle,&info)||
           !(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
           (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
           !windowsHandleMatchesPath(handle,current))return {};
    }
    return chain;
}
#endif

bool openSecurePartial(QFile& file,const QString& path,bool append,
                       std::shared_ptr<PinnedDirectoryChain>* pinnedChain = nullptr
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                       ,const FileTransferService::AtomicPublishTestHooks* testHooks = nullptr
#endif
                       )
{
#ifdef Q_OS_WIN
    auto chain=pinParentChain(path);
    if(!chain)return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    if(testHooks!=nullptr&&testHooks->phase)
        testHooks->phase(FileTransferService::AtomicPublishPhase::PartialParentPinned,path);
#endif
    HANDLE handle=openRelativeToDirectory(chain->handles.back(),QFileInfo(path).fileName(),
        GENERIC_READ|GENERIC_WRITE|DELETE|SYNCHRONIZE,FILE_SHARE_READ,
        append?kNtFileOpen:kNtFileCreate,
        kNtFileSynchronousNonAlert|kNtFileNonDirectory|kNtFileOpenReparsePoint);
    if(handle==INVALID_HANDLE_VALUE)return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle,&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
       !windowsHandleMatchesPath(handle,path)){CloseHandle(handle);return false;}
    LARGE_INTEGER zero{};
    if(!SetFilePointerEx(handle,zero,nullptr,append?FILE_END:FILE_BEGIN)){CloseHandle(handle);return false;}
    const int fd=_open_osfhandle(reinterpret_cast<intptr_t>(handle),_O_BINARY|_O_RDWR|_O_NOINHERIT);
    if(fd<0){CloseHandle(handle);return false;}
    if(!file.open(fd,QIODevice::ReadWrite,QFileDevice::AutoCloseHandle)){_close(fd);return false;}
    if(pinnedChain!=nullptr)*pinnedChain=std::move(chain);
    return append?file.seek(file.size()):file.seek(0);
#else
    Q_UNUSED(pinnedChain);
    if(QFileInfo(path).isSymLink())return false;
    return file.open(append?(QIODevice::ReadWrite|QIODevice::Append):(QIODevice::ReadWrite|QIODevice::NewOnly));
#endif
}

std::optional<QByteArray> readSecureLeaf(const QString& path)
{
#ifdef Q_OS_WIN
    auto chain=pinParentChain(path);if(!chain)return std::nullopt;
    HANDLE handle=openRelativeToDirectory(chain->handles.back(),QFileInfo(path).fileName(),
        GENERIC_READ|SYNCHRONIZE,FILE_SHARE_READ,kNtFileOpen,
        kNtFileSynchronousNonAlert|kNtFileNonDirectory|kNtFileOpenReparsePoint);
    if(handle==INVALID_HANDLE_VALUE)return std::nullopt;
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle,&info)||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
       !windowsHandleMatchesPath(handle,path)){CloseHandle(handle);return std::nullopt;}
    const int fd=_open_osfhandle(reinterpret_cast<intptr_t>(handle),_O_BINARY|_O_RDONLY|_O_NOINHERIT);
    if(fd<0){CloseHandle(handle);return std::nullopt;}
    QFile file(path);
    if(!file.open(fd,QIODevice::ReadOnly,QFileDevice::AutoCloseHandle)){_close(fd);return std::nullopt;}
    if(file.size()>FileTransferResume::MaxManifestBytes)return std::nullopt;
    return file.readAll();
#else
    Q_UNUSED(path);return std::nullopt;
#endif
}

#ifdef Q_OS_WIN
bool renameHandleRelative(HANDLE handle,HANDLE parentHandle,const QString& targetLeaf,bool replace)
{
    const std::wstring targetName=targetLeaf.toStdWString();
    const DWORD targetBytes=DWORD(targetName.size()*sizeof(wchar_t));
    std::vector<std::byte> storage(sizeof(FILE_RENAME_INFO)+targetBytes);
    auto* info=reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    info->ReplaceIfExists=replace?TRUE:FALSE;
    info->RootDirectory=parentHandle;
    info->FileNameLength=targetBytes;
    std::memcpy(info->FileName,targetName.data(),targetBytes);
    using NtSetInformationFileFn=NTSTATUS(NTAPI*)(
        HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
    using RtlNtStatusToDosErrorFn=ULONG(NTAPI*)(NTSTATUS);
    const HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    const auto ntSetInformationFile=ntdll?reinterpret_cast<NtSetInformationFileFn>(
        GetProcAddress(ntdll,"NtSetInformationFile")):nullptr;
    const auto rtlNtStatusToDosError=ntdll?reinterpret_cast<RtlNtStatusToDosErrorFn>(
        GetProcAddress(ntdll,"RtlNtStatusToDosError")):nullptr;
    if(!ntSetInformationFile||!rtlNtStatusToDosError){SetLastError(ERROR_PROC_NOT_FOUND);return false;}
    IO_STATUS_BLOCK ioStatus{};
    constexpr ULONG kFileRenameInformation=10;
    const NTSTATUS status=ntSetInformationFile(handle,&ioStatus,info,
        ULONG(storage.size()),kFileRenameInformation);
    if(status<0){SetLastError(rtlNtStatusToDosError(status));return false;}
    return true;
}
#endif

bool writeSecureLeaf(const QString& path,const QByteArray& data,QString* error
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                     ,const std::function<bool()>* failPromotion = nullptr
#endif
                     )
{
#ifdef Q_OS_WIN
    auto chain=pinParentChain(path);
    if(!chain){if(error)*error=QObject::tr("diretório do manifesto não pôde ser fixado");return false;}
    const QString tempLeaf=QStringLiteral(".inputleap-manifest-tmp-%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    const QString tempPath=QDir(QFileInfo(path).absolutePath()).filePath(tempLeaf);
    HANDLE handle=openRelativeToDirectory(chain->handles.back(),tempLeaf,
        GENERIC_READ|GENERIC_WRITE|DELETE|SYNCHRONIZE,FILE_SHARE_READ,kNtFileCreate,
        kNtFileSynchronousNonAlert|kNtFileNonDirectory|kNtFileOpenReparsePoint);
    if(handle==INVALID_HANDLE_VALUE){if(error)*error=QObject::tr("não foi possível criar o manifesto temporário fixado");return false;}
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle,&info)||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
       !windowsHandleMatchesPath(handle,tempPath)){CloseHandle(handle);if(error)*error=QObject::tr("manifesto temporário redirecionado");return false;}
    const int fd=_open_osfhandle(reinterpret_cast<intptr_t>(handle),_O_BINARY|_O_RDWR|_O_NOINHERIT);
    if(fd<0){CloseHandle(handle);return false;}
    QFile file(tempPath);
    if(!file.open(fd,QIODevice::ReadWrite,QFileDevice::AutoCloseHandle)){_close(fd);return false;}
    const auto discardTemp=[&]{
        FILE_DISPOSITION_INFO_EX disposition{};
        disposition.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS|
                          FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
        SetFileInformationByHandle(reinterpret_cast<HANDLE>(_get_osfhandle(file.handle())),
                                   FileDispositionInfoEx,&disposition,sizeof(disposition));
    };
    if(file.write(data)!=data.size()||!file.flush()){
        discardTemp();if(error)*error=QObject::tr("não foi possível gravar o manifesto temporário");return false;
    }
    const intptr_t native=_get_osfhandle(file.handle());
    if(native==-1||!FlushFileBuffers(reinterpret_cast<HANDLE>(native))){
        discardTemp();if(error)*error=QObject::tr("não foi possível confirmar o manifesto temporário");return false;
    }
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    if(failPromotion!=nullptr&&*failPromotion&&(*failPromotion)()){
        discardTemp();if(error)*error=QObject::tr("falha de promoção injetada pelo teste");return false;
    }
#endif
    if(!renameHandleRelative(reinterpret_cast<HANDLE>(native),chain->handles.back(),
                             QFileInfo(path).fileName(),true)){
        discardTemp();if(error)*error=QObject::tr("não foi possível promover atomicamente o manifesto");return false;
    }
    if(!windowsHandleMatchesPath(reinterpret_cast<HANDLE>(native),path)){
        if(error)*error=QObject::tr("manifesto promovido não corresponde ao destino");return false;
    }
    return true;
#else
    Q_UNUSED(path);Q_UNUSED(data);
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    Q_UNUSED(failPromotion);
#endif
    if(error)*error=QObject::tr("manifesto seguro indisponível nesta plataforma");return false;
#endif
}

bool removeSecureLeaf(const QString& path)
{
#ifdef Q_OS_WIN
    auto chain=pinParentChain(path);if(!chain)return false;
    HANDLE handle=openRelativeToDirectory(chain->handles.back(),QFileInfo(path).fileName(),
        DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE,kNtFileOpen,
        kNtFileSynchronousNonAlert|kNtFileNonDirectory|kNtFileOpenReparsePoint);
    if(handle==INVALID_HANDLE_VALUE)return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(handle,&info)||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
       !windowsHandleMatchesPath(handle,path)){CloseHandle(handle);return false;}
    FILE_DISPOSITION_INFO_EX disposition{};
    disposition.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS|
                      FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    const bool removed=SetFileInformationByHandle(handle,FileDispositionInfoEx,
                                                   &disposition,sizeof(disposition))!=FALSE;
    CloseHandle(handle);return removed;
#else
    Q_UNUSED(path);return false;
#endif
}

bool atomicPublish(QFile& sourceFile,const QString& source,const QString& destination,bool replace,
                   QFile* authorizedExisting = nullptr,
                   QString* recoveryPath = nullptr,
                   std::shared_ptr<PinnedDirectoryChain> destinationChain = {},
                   std::function<bool(const QString&)> prepareRecovery = {},
                   std::function<bool(const QString&)> commitRecovery = {}
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                   ,const FileTransferService::AtomicPublishTestHooks* testHooks = nullptr
#endif
                   )
{
#ifdef Q_OS_WIN
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    const auto notifyPhase=[&](FileTransferService::AtomicPublishPhase phase,
                               const QString& path = QString()) {
        if(testHooks!=nullptr&&testHooks->phase)testHooks->phase(phase,path);
    };
    const auto failOperation=[&](FileTransferService::AtomicPublishOperation operation) {
        return testHooks!=nullptr&&testHooks->failOperation&&testHooks->failOperation(operation);
    };
#endif
    const QFileInfo destinationInfo(destination);
    const QString leaf=destinationInfo.fileName();
    if(leaf.isEmpty()||leaf==QStringLiteral(".")||leaf==QStringLiteral("..")||
       leaf.contains('/')||leaf.contains('\\'))return false;
    auto pinnedDirectories=destinationChain?std::move(destinationChain):pinParentChain(destination);
    if(!pinnedDirectories)return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    notifyPhase(FileTransferService::AtomicPublishPhase::AncestorsPinned);
#endif

    if(!sourceFile.isOpen())return false;
    const intptr_t nativeSourceHandle=_get_osfhandle(sourceFile.handle());
    if(nativeSourceHandle==-1)return false;
    const HANDLE sourceHandle=reinterpret_cast<HANDLE>(nativeSourceHandle);
    BY_HANDLE_FILE_INFORMATION sourceInfo{};
    if(!GetFileInformationByHandle(sourceHandle,&sourceInfo)||
       (sourceInfo.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||
       !windowsHandleMatchesPath(sourceHandle,source))return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    notifyPhase(FileTransferService::AtomicPublishPhase::SourcePinned);
#endif

    const HANDLE destinationParentHandle=pinnedDirectories->handles.back();
    const auto renameHandle=[destinationParentHandle](HANDLE handle,const QString& targetLeaf){
        const std::wstring targetName=targetLeaf.toStdWString();
        const DWORD targetBytes=DWORD(targetName.size()*sizeof(wchar_t));
        const size_t renameBytes=sizeof(FILE_RENAME_INFO)+targetBytes;
        std::vector<std::byte> renameStorage(renameBytes);
        auto* renameInfo=reinterpret_cast<FILE_RENAME_INFO*>(renameStorage.data());
        renameInfo->ReplaceIfExists=FALSE;
        renameInfo->RootDirectory=destinationParentHandle;
        renameInfo->FileNameLength=targetBytes;
        std::memcpy(renameInfo->FileName,targetName.data(),targetBytes);
        using NtSetInformationFileFn=NTSTATUS(NTAPI*)(
            HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
        using RtlNtStatusToDosErrorFn=ULONG(NTAPI*)(NTSTATUS);
        const HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
        const auto ntSetInformationFile=ntdll?reinterpret_cast<NtSetInformationFileFn>(
            GetProcAddress(ntdll,"NtSetInformationFile")):nullptr;
        const auto rtlNtStatusToDosError=ntdll?reinterpret_cast<RtlNtStatusToDosErrorFn>(
            GetProcAddress(ntdll,"RtlNtStatusToDosError")):nullptr;
        if(!ntSetInformationFile||!rtlNtStatusToDosError){SetLastError(ERROR_PROC_NOT_FOUND);return false;}
        IO_STATUS_BLOCK ioStatus{};
        constexpr ULONG kFileRenameInformation=10;
        const NTSTATUS status=ntSetInformationFile(handle,&ioStatus,renameInfo,
            ULONG(renameStorage.size()),kFileRenameInformation);
        if(status<0){SetLastError(rtlNtStatusToDosError(status));return false;}
        return true;
    };

    if(!replace){
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        if(failOperation(FileTransferService::AtomicPublishOperation::PublishSource))return false;
#endif
        if(!renameHandle(sourceHandle,leaf))return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        notifyPhase(FileTransferService::AtomicPublishPhase::Committed);
#endif
        return true;
    }

    if(authorizedExisting==nullptr||!authorizedExisting->isOpen())return false;
    const intptr_t nativeExisting=_get_osfhandle(authorizedExisting->handle());
    if(nativeExisting==-1)return false;
    const HANDLE existingHandle=reinterpret_cast<HANDLE>(nativeExisting);
    const QString recoveryLeaf=QStringLiteral("InputLeap original %1 - %2").arg(
        QUuid::createUuid().toString(QUuid::WithoutBraces),leaf.left(160));
    const QString visibleRecovery=QDir(destinationInfo.absolutePath()).filePath(recoveryLeaf);
    if(!prepareRecovery||!prepareRecovery(visibleRecovery))return false;
    if(!renameHandle(existingHandle,recoveryLeaf))return false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    notifyPhase(FileTransferService::AtomicPublishPhase::ExistingMoved,visibleRecovery);
#endif
    bool publishFailed=false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    publishFailed=failOperation(FileTransferService::AtomicPublishOperation::PublishSource);
#endif
    if(publishFailed||!renameHandle(sourceHandle,leaf)){
        bool rollbackFailed=false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        rollbackFailed=failOperation(FileTransferService::AtomicPublishOperation::RollbackOriginal);
#endif
        if((rollbackFailed||!renameHandle(existingHandle,leaf))&&recoveryPath!=nullptr)
            *recoveryPath=visibleRecovery;
        return false;
    }

    if(!commitRecovery||!commitRecovery(visibleRecovery)){
        if(recoveryPath!=nullptr)*recoveryPath=visibleRecovery;
        return false;
    }

#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    notifyPhase(FileTransferService::AtomicPublishPhase::Committed,visibleRecovery);
    notifyPhase(FileTransferService::AtomicPublishPhase::BeforeCleanup,visibleRecovery);
#endif
    FILE_DISPOSITION_INFO_EX disposition{};
    disposition.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS|
                      FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    bool cleanupFailed=false;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    cleanupFailed=failOperation(FileTransferService::AtomicPublishOperation::CleanupOriginal);
#endif
    if((cleanupFailed||!SetFileInformationByHandle(existingHandle,FileDispositionInfoEx,
                                                    &disposition,sizeof(disposition)))&&
       recoveryPath!=nullptr)
        *recoveryPath=visibleRecovery;
    return true;
#else
    Q_UNUSED(sourceFile);
    Q_UNUSED(source);
    Q_UNUSED(destination);
    Q_UNUSED(replace);
    Q_UNUSED(authorizedExisting);
    Q_UNUSED(recoveryPath);
    Q_UNUSED(destinationChain);
    Q_UNUSED(prepareRecovery);
    Q_UNUSED(commitRecovery);
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    Q_UNUSED(testHooks);
#endif
    // POSIX rename() may overwrite a leaf that was swapped after authorization,
    // and POSIX share modes do not pin a pathname to this verified QFile handle.
    // Fail closed until a platform primitive with equivalent handle-relative,
    // no-replace semantics is available.
    return false;
#endif
}

void cleanse(QByteArray& value)
{
    value.detach();
    if (!value.isEmpty()) OPENSSL_cleanse(value.data(), size_t(value.size()));
    value.clear();
}

QByteArray deviceIdentity(const QUuid& uuid)
{
    return kDeviceIdentityPrefix + uuid.toString(QUuid::WithoutBraces).toLower().toLatin1();
}

bool configureTlsPsk(QSslSocket* socket)
{
    QList<QSslCipher> pskCiphers;
    const QStringList allowedCipherNames = FileTransferService::tlsPskCipherNames();
    for (const QSslCipher& cipher : QSslConfiguration::defaultConfiguration().supportedCiphers()) {
        if (allowedCipherNames.contains(cipher.name())) {
            pskCiphers.append(cipher);
        }
    }
    if (pskCiphers.isEmpty()) {
        return false;
    }

    QSslConfiguration configuration = socket->sslConfiguration();
    configuration.setProtocol(QSsl::TlsV1_2);
    configuration.setCiphers(pskCiphers);
    socket->setSslConfiguration(configuration);
    socket->setPeerVerifyMode(QSslSocket::VerifyNone);
    return true;
}

struct ReceiveState
{
    ~ReceiveState()
    {
        clearSecrets();
    }

    void clearSecrets()
    {
        cleanse(sessionKey);
        cleanse(manifestKey);
        cleanse(securityToken);
    }

    bool headerParsed = false;
    bool headerRead = false;
    QString fileName;
    QString destinationPath;
    QByteArray expectedSha256;
    QCryptographicHash hash = QCryptographicHash(QCryptographicHash::Sha256);
    quint64 expectedSize = 0;
    quint64 receivedSize = 0;
    quint64 lastProgressSize = 0;
    quint64 lastCheckpointSize = 0;
    QFile* file = nullptr;
    quint16 version = 1;
    QByteArray transferId;
    QByteArray storageId;
    QUuid peerUuid;
    quint32 itemIndex = 0;
    QByteArray batchId;
    quint32 itemCount = 1;
    ConflictAction conflictAction = ConflictAction::Rename;
    QByteArray sessionKey;
    QByteArray manifestKey;
    QByteArray securityToken;
    QString manifestPath;
    QString partPath;
    std::optional<FileTransferResume::Manifest> resumeManifest;
    std::shared_ptr<PinnedDirectoryChain> partialDirectoryChain;
    quint64 resumeOffset=0;
    bool permissionChecked=false;
    bool existingHashPending=false;
    bool existingHashReady=false;
    HashResult existingHash;
    FileIdentity authorizedDestinationIdentity;
    std::shared_ptr<std::atomic_bool> cancelled=std::make_shared<std::atomic_bool>(false);
};

class TlsPskServer final : public QTcpServer
{
public:
    using QTcpServer::QTcpServer;

    ~TlsPskServer() override { cleanse(legacy_key_); for(auto& key:device_keys_) cleanse(key); }
    void setPreSharedKey(QByteArray key) {
        key.detach();
        cleanse(legacy_key_);
        legacy_key_ = std::move(key);
    }
    void setDeviceKey(const QUuid& uuid,const QByteArray& key) {
        if(uuid.isNull()||key.size()!=32)return;
        auto it=device_keys_.find(uuid); if(it!=device_keys_.end())cleanse(it.value());
        QByteArray owned=key;owned.detach();device_keys_.insert(uuid,std::move(owned));
    }
    void removeDeviceKey(const QUuid& uuid) {
        auto it=device_keys_.find(uuid);if(it==device_keys_.end())return;cleanse(it.value());device_keys_.erase(it);
    }
    void clearKeys() {
        cleanse(legacy_key_);
        legacy_key_.clear();
        for (auto& key : device_keys_) cleanse(key);
        device_keys_.clear();
    }
    bool hasLegacyKey() const { return !legacy_key_.isEmpty(); }

protected:
    void incomingConnection(qintptr socketDescriptor) override
    {
        auto* socket = new QSslSocket(this);
        if (!socket->setSocketDescriptor(socketDescriptor)) {
            socket->deleteLater();
            return;
        }

        if (!legacy_key_.isEmpty() || !device_keys_.isEmpty()) {
            connect(socket, &QSslSocket::preSharedKeyAuthenticationRequired, socket,
                    [this,socket](QSslPreSharedKeyAuthenticator* authenticator) {
                        const QByteArray identity=authenticator->identity();
                        if(identity==kLegacyTlsPskIdentity){authenticator->setPreSharedKey(legacy_key_);return;}
                        if(!identity.startsWith(kDeviceIdentityPrefix)){authenticator->setPreSharedKey({});return;}
                        const QByteArray uuidText=identity.mid(kDeviceIdentityPrefix.size());
                        const QUuid uuid(QString::fromLatin1(uuidText));
                        if(uuid.isNull()||uuidText!=uuid.toString(QUuid::WithoutBraces).toLower().toLatin1()){authenticator->setPreSharedKey({});return;}
                        const auto it=device_keys_.constFind(uuid);
                        if(it==device_keys_.cend()){authenticator->setPreSharedKey({});return;}
                        socket->setProperty("fileTransferPeerUuid",uuid);
                        auto* state = static_cast<ReceiveState*>(
                            socket->property("fileTransferState").value<void*>());
                        if (state != nullptr) {
                            cleanse(state->sessionKey);
                            cleanse(state->manifestKey);
                            state->sessionKey = it.value();
                            state->sessionKey.detach();
                            state->manifestKey = FileTransferResume::deriveContextKey(
                                it.value(), "manifest-v1");
                            state->manifestKey.detach();
                        }
                        authenticator->setPreSharedKey(it.value());
                    });
            if (!configureTlsPsk(socket)) {
                socket->disconnectFromHost();
                socket->deleteLater();
                return;
            }
            socket->setProperty("fileTransferUseTls", true);
        }
        addPendingConnection(socket);
    }

private:
    QByteArray legacy_key_;
    QHash<QUuid,QByteArray> device_keys_;
};
}

#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
bool FileTransferService::secureDirectoryForTests(const QString& directory)
{
    return ensureSecureDirectory(directory);
}

bool FileTransferService::atomicPublishForTests(
    const QString& source, const QString& destination, bool replace,
    const AtomicPublishTestHooks& hooks, QString* recoveryPath)
{
    QFile sourceFile(source);
    if(!openSecurePartial(sourceFile,source,true))return false;
    HashResult existing;
    QFile* authorizedExisting=nullptr;
    if(replace){
        existing=hashDirectFile(destination,std::make_shared<std::atomic_bool>(false));
        if(!existing.ok||!existing.deleteAccess||!existing.lock)return false;
        authorizedExisting=existing.lock.get();
    }
    const bool published=atomicPublish(sourceFile,source,destination,replace,
                                       authorizedExisting,recoveryPath,{},
                                       [](const QString&){return true;},
                                       [](const QString&){return true;},&hooks);
    sourceFile.close();
    existing.lock.reset();
    return published;
}
#endif

QStringList FileTransferService::tlsPskCipherNames()
{
    const QStringList preferredCipherNames = {
        QStringLiteral("PSK-AES256-GCM-SHA384"),
        QStringLiteral("PSK-AES128-GCM-SHA256"),
        QStringLiteral("PSK-AES256-CBC-SHA384"),
        QStringLiteral("PSK-AES128-CBC-SHA256")
    };

    QStringList supportedNames;
    for (const QSslCipher& cipher : QSslConfiguration::defaultConfiguration().supportedCiphers()) {
        if (preferredCipherNames.contains(cipher.name())) {
            supportedNames.append(cipher.name());
        }
    }
    return supportedNames;
}

QByteArray calculateSha256(QFile& file, const FileTransferService::CancelCallback& cancelCallback)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        if (cancelCallback && cancelCallback()) {
            return {};
        }
        const QByteArray chunk=file.read(kChunkSize);
        if(chunk.isEmpty()&&!file.atEnd())return {};
        hash.addData(chunk);
    }
    file.seek(0);
    return hash.result();
}

FileTransferService::FileTransferService(QObject* parent) :
    QObject(parent),
    server_(new TlsPskServer(this))
{
    connect(server_, &QTcpServer::newConnection, this, &FileTransferService::acceptConnection);
}

FileTransferService::~FileTransferService()
{
    for(QTcpSocket* socket:server_->findChildren<QTcpSocket*>()){
        auto* state=static_cast<ReceiveState*>(socket->property("fileTransferState").value<void*>());
        if(state){state->cancelled->store(true);state->clearSecrets();}
    }
}

bool FileTransferService::startListening(quint16 port, QString* errorMessage)
{
    if (server_->isListening()) {
        server_->close();
    }

    if (!server_->listen(QHostAddress::Any, port)) {
        if (errorMessage != nullptr) {
            *errorMessage = server_->errorString();
        }
        return false;
    }

    port_ = server_->serverPort();
    emit info(tr("file transfer receiver listening on port %1").arg(port_));
    return true;
}

void FileTransferService::stopListening()
{
    server_->close();
    port_ = 0;
    for (QTcpSocket* socket : server_->findChildren<QTcpSocket*>()) {
        auto* state = static_cast<ReceiveState*>(
            socket->property("fileTransferState").value<void*>());
        if (state) { state->cancelled->store(true); state->clearSecrets(); }
        socket->abort();
    }
}

QString FileTransferService::receiveDirectory() const
{
    if (!receive_directory_.trimmed().isEmpty()) {
        return QDir(receive_directory_).absolutePath();
    }

    QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (downloads.isEmpty()) {
        downloads = QDir::homePath();
    }

    return QDir(downloads).filePath("InputLeap");
}

void FileTransferService::setReceiveDirectory(const QString& directory)
{
    receive_directory_ = directory;
}

void FileTransferService::setPairingCode(const QString& pairingCode)
{
    static_cast<TlsPskServer*>(server_)->setPreSharedKey(pairingKeyForCode(pairingCode));
}

void FileTransferService::clearPreSharedKeys()
{
    static_cast<TlsPskServer*>(server_)->clearKeys();
}

bool FileTransferService::legacyPairingEnabled() const
{
    return static_cast<const TlsPskServer*>(server_)->hasLegacyKey();
}

void FileTransferService::setDevicePreSharedKey(const QUuid& peerUuid,const QByteArray& key)
{
    static_cast<TlsPskServer*>(server_)->setDeviceKey(peerUuid,key);
}

void FileTransferService::removeDevicePreSharedKey(const QUuid& peerUuid)
{
    if(!peerUuid.isNull()){
        static_cast<TlsPskServer*>(server_)->removeDeviceKey(peerUuid);
        conflict_policy_.resetPeer(peerUuid);
    }
}

void FileTransferService::setIncomingFileCallback(IncomingFileCallback callback)
{
    incoming_file_callback_ = std::move(callback);
}

void FileTransferService::setReceivePermissionCallback(PermissionCallback callback)
{
    receive_permission_callback_ = std::move(callback);
}

void FileTransferService::setConflictCallback(ConflictCallback callback)
{
    conflict_callback_ = std::move(callback);
}

bool FileTransferService::isSafeToOpenAutomatically(const QString& fileName)
{
    static const QSet<QString> dangerousSuffixes = {
        QStringLiteral("exe"), QStringLiteral("msi"), QStringLiteral("bat"),
        QStringLiteral("cmd"), QStringLiteral("ps1"), QStringLiteral("vbs"),
        QStringLiteral("js"), QStringLiteral("lnk")
    };
    return !dangerousSuffixes.contains(QFileInfo(fileName).suffix().toLower());
}

QByteArray FileTransferService::pairingKeyForCode(const QString& pairingCode)
{
    QString normalizedText = pairingCode.trimmed();
    const auto cleanseText = qScopeGuard([&normalizedText] {
        if (!normalizedText.isEmpty())
            OPENSSL_cleanse(normalizedText.data(),
                            static_cast<size_t>(normalizedText.size() * sizeof(QChar)));
    });
    QByteArray normalizedCode = normalizedText.toUtf8();
    const auto cleanseCode = qScopeGuard([&normalizedCode] {
        if (!normalizedCode.isEmpty())
            OPENSSL_cleanse(normalizedCode.data(), static_cast<size_t>(normalizedCode.size()));
    });
    if (normalizedCode.isEmpty()) {
        return {};
    }
    return QCryptographicHash::hash(normalizedCode, QCryptographicHash::Sha256);
}

QString FileTransferService::uniqueDestinationPath(const QString& fileName) const
{
    QString relativePath = QDir::cleanPath(fileName);
    while (relativePath.startsWith("../")) {
        relativePath.remove(0, 3);
    }
    if (relativePath == ".." || QDir::isAbsolutePath(relativePath)) {
        relativePath = QFileInfo(relativePath).fileName();
    }

    const QFileInfo info(relativePath);
    const QString baseName = info.completeBaseName().isEmpty() ? QStringLiteral("received-file") : info.completeBaseName();
    const QString suffix = info.suffix();
    QDir dir(receiveDirectory());

    const QString relativeDir = info.path() == "." ? QString() : info.path();

    QString candidate = dir.filePath(relativePath);
    int index = 1;
    while (QFileInfo::exists(candidate)) {
        const QString numbered = suffix.isEmpty()
            ? QString("%1 (%2)").arg(baseName).arg(index)
            : QString("%1 (%2).%3").arg(baseName).arg(index).arg(suffix);
        candidate = relativeDir.isEmpty() ? dir.filePath(numbered) : dir.filePath(QDir(relativeDir).filePath(numbered));
        ++index;
    }

    return candidate;
}

void FileTransferService::acceptConnection()
{
    while (QTcpSocket* socket = server_->nextPendingConnection()) {
        auto* state = new ReceiveState();
        socket->setProperty("fileTransferState", QVariant::fromValue<void*>(state));

        if (socket->property("fileTransferUseTls").toBool()) {
            static_cast<QSslSocket*>(socket)->startServerEncryption();
        }

        connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
            readIncoming(socket);
        });
        connect(socket, &QTcpSocket::disconnected, this, [this,socket]() {
            auto* state = static_cast<ReceiveState*>(socket->property("fileTransferState").value<void*>());
            if (state != nullptr) {
                state->cancelled->store(true);
                socket->setProperty("fileTransferState",QVariant::fromValue<void*>(nullptr));
                if(!state->storageId.isEmpty())active_resume_ids_.remove(state->storageId);
                if (state->file != nullptr) {
                    state->file->close();
                    delete state->file;
                }
                delete state;
            }
            socket->deleteLater();
        });
    }
}

void FileTransferService::readIncoming(QTcpSocket* socket)
{
    auto* state = static_cast<ReceiveState*>(socket->property("fileTransferState").value<void*>());
    if (state == nullptr) {
        socket->disconnectFromHost();
        return;
    }
    const auto ensureReceiveDirectory=[this](const QString& path){
        return ensureSecureDirectory(path
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                                     ,&atomic_publish_test_hooks_
#endif
                                     );
    };
    const auto persistManifest=[this](const QString& path,const QByteArray& encoded,
                                      const FileTransferResume::Manifest& manifest,
                                      QString* error){
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        if(atomic_publish_test_hooks_.failManifestWrite&&
           atomic_publish_test_hooks_.failManifestWrite(
               manifest.completed,!manifest.recoveryPath.isEmpty())){
            if(error)*error=tr("falha de manifesto injetada pelo teste");
            return false;
        }
#endif
        return writeSecureLeaf(path,encoded,error
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                               ,&atomic_publish_test_hooks_.failManifestPromotion
#endif
                               );
    };

    if (!state->headerRead) {
        if(!state->headerParsed){
        QDataStream in(socket);
        in.setVersion(QDataStream::Qt_6_0);
        in.startTransaction();

        quint32 magic = 0;
        in >> magic;
        if (magic == kMagic) {
            in >> state->version;
            if (state->version >= 3) {
                in >> state->transferId >> state->itemIndex;
                if(state->version>=4)in >> state->batchId >> state->itemCount;
                if(state->version>=5)in >> state->securityToken;
                in >> state->fileName >> state->expectedSize >> state->expectedSha256;
                state->peerUuid=socket->property("fileTransferPeerUuid").toUuid();
            }
            else if (state->version >= 2) in >> state->fileName >> state->expectedSize >> state->expectedSha256;
            else in >> state->fileName >> state->expectedSize;
        }
        if (!in.commitTransaction()) {
            return;
        }

        if (magic != kMagic || state->version > kProtocolVersion || state->fileName.isEmpty() ||
            state->expectedSize>FileTransferResume::MaxFileBytes ||
            (state->version>=3 && (state->transferId.size()!=16 || state->peerUuid.isNull() || state->manifestKey.size()!=32 ||
                                  state->itemIndex>=10000 || !FileTransferResume::isSafeRelativePath(state->fileName) ||
                                  state->fileName.toUtf8().size()>FileTransferResume::MaxRelativePathUtf8 ||
                                  state->expectedSha256.size()!=32)) ||
            (state->version>=4 && (state->batchId.size()!=16 || state->itemCount==0 || state->itemIndex>=state->itemCount)) ||
            (state->version>=5 && state->securityToken.isEmpty())) {
            emit error(tr("invalid file transfer request"));
            socket->disconnectFromHost();
            return;
        }
        if (!state->peerUuid.isNull() && state->sessionKey.size() == 32 &&
            state->version < 5) {
            emit info(tr("Transferência recebida bloqueada: versão autenticada obrigatória."));
            emit fileRejected({}, {});
            socket->write(QByteArray(1, kTransferRejected));
            socket->waitForBytesWritten(kWriteTimeoutMs);
            socket->disconnectFromHost();
            return;
        }
        if (state->version >= 5) {
            const auto endpoint = ProtocolSecurityPolicy::canonicalEndpoint(socket->localAddress(), socket->localPort());
            const bool accepted = endpoint && security_policy_.accept(state->securityToken, state->peerUuid, state->peerUuid,
                                         *endpoint, {"file-transfer:5"}, state->sessionKey);
            if (!accepted) {
                emit info(tr("Transferência recebida bloqueada: autorização inválida."));
                emit fileRejected({}, {});
                socket->write(QByteArray(1, kTransferRejected));
                socket->waitForBytesWritten(kWriteTimeoutMs);
                socket->disconnectFromHost();
                return;
            }
        }
        // Authorization is the first protocol-side effect after the authenticated
        // identity has been validated. It also covers resumed transfers and fails closed.
        if (!state->permissionChecked) {
            if (state->peerUuid.isNull() || !receive_permission_callback_ ||
                !receive_permission_callback_(state->peerUuid)) {
                emit info(tr("Transferência recebida bloqueada: permissão não concedida."));
                emit fileRejected({}, {});
                socket->write(QByteArray(1, kTransferRejected));
                socket->waitForBytesWritten(kWriteTimeoutMs);
                socket->disconnectFromHost();
                return;
            }
            state->permissionChecked = true;
        }
        if(state->version>=3){
            state->storageId=FileTransferResume::scopedStorageId(state->peerUuid,state->transferId);
            if(state->storageId.isEmpty()||active_resume_ids_.contains(state->storageId)){emit error(tr("esta retomada já está ativa"));socket->disconnectFromHost();return;}
            active_resume_ids_.insert(state->storageId);
        }
        const QString receiveRoot=receiveDirectory();
        const QString relativeParent=QFileInfo(state->fileName).path();
        const QString destinationParent=relativeParent=="."?receiveRoot:QDir(receiveRoot).filePath(relativeParent);
        state->headerParsed=true;
        }

        const QString displayName = QFileInfo(state->fileName).fileName();
        const QString requestedPath=QDir(receiveDirectory()).filePath(state->fileName);
        const QString peerAddress = socket->peerAddress().toString();
        quint64& resumeOffset=state->resumeOffset;
        bool authenticatedManifestPresent=false;
        if(state->version>=3){
            state->partPath=FileTransferResume::partPath(receiveDirectory(),state->storageId);
            state->manifestPath=FileTransferResume::manifestPath(receiveDirectory(),state->storageId);
            const bool manifestObserved=QFileInfo::exists(state->manifestPath);
            const auto manifestBytes=readSecureLeaf(state->manifestPath);
            if(manifestBytes){
                QString manifestError;
                const auto saved=FileTransferResume::decodeManifest(
                    *manifestBytes,state->manifestKey,state->peerUuid,&manifestError);
                if(!saved){
                    emit error(tr("manifesto autenticado inválido; estado preservado para recuperação manual: %1")
                                   .arg(manifestError));
                    socket->disconnectFromHost();return;
                }
                authenticatedManifestPresent=true;
                const bool same=saved->transferId==state->transferId && saved->itemIndex==state->itemIndex && saved->relativePath==state->fileName &&
                    saved->expectedSize==state->expectedSize && FileTransferResume::constantTimeEqual(saved->sha256,state->expectedSha256);
                if(!same){emit error(tr("identidade de retomada conflitante"));socket->disconnectFromHost();return;}
                bool alreadyComplete=false;
                bool publicationNeedsReview=false;
                const bool shouldValidatePublished=saved->completed||
                    (saved->recoveryPath.isEmpty()&&!saved->publishedPath.isEmpty()&&
                     !QFileInfo::exists(state->partPath));
                if(same&&shouldValidatePublished){
                    QFile published(saved->publishedPath);
                    alreadyComplete=published.open(QIODevice::ReadOnly)&&openedFileStillMatchesPath(published,saved->publishedPath)&&
                        quint64(published.size())==saved->expectedSize&&FileTransferResume::constantTimeEqual(calculateSha256(published,{}),saved->sha256);
                    publicationNeedsReview=!alreadyComplete;
                }
                // Revalidate immediately after resume state is resolved, including the
                // already-complete fast path, before recording completion or replying success.
                if (!receive_permission_callback_ ||
                    !receive_permission_callback_(state->peerUuid)) {
                    emit info(tr("Transferência recebida bloqueada: permissão não concedida."));
                    emit fileRejected({}, {});
                    socket->write(QByteArray(1, kTransferRejected));
                    socket->waitForBytesWritten(kWriteTimeoutMs);
                    socket->disconnectFromHost();
                    return;
                }
                if(same&&!saved->completed&&!saved->recoveryPath.isEmpty()){
                    const QString terminalName=QFileInfo(state->fileName).fileName();
                    emit publicationCompleted(terminalName,
                        {PublicationStatus::RecoveryRequired,saved->publishedPath,
                         saved->recoveryPath,state->peerUuid,state->transferId});
                    emit fileRejected(terminalName,peerAddress,state->transferId);
                    emit error(tr("a publicação anterior exige recuperação em %1")
                                   .arg(saved->recoveryPath));
                    socket->write(QByteArray(1,kTransferRejected));
                    socket->waitForBytesWritten(kWriteTimeoutMs);
                    socket->disconnectFromHost();return;
                }
                if(publicationNeedsReview){
                    const QString terminalName=QFileInfo(state->fileName).fileName();
                    emit publicationCompleted(terminalName,
                        {PublicationStatus::ReviewRequired,saved->publishedPath,{},
                         state->peerUuid,state->transferId});
                    emit fileRejected(terminalName,peerAddress,state->transferId);
                    emit error(tr("a publicação anterior está indeterminada; verifique manualmente %1")
                                   .arg(saved->publishedPath));
                    socket->write(QByteArray(1,kTransferRejected));
                    socket->waitForBytesWritten(kWriteTimeoutMs);
                    socket->disconnectFromHost();return;
                }
                if(alreadyComplete){
                    if(state->version>=4){
                        conflict_policy_.recordNonConflict({state->peerUuid,state->batchId,state->transferId,state->fileName,requestedPath,state->itemIndex,state->itemCount});
                        if(state->itemIndex+1==state->itemCount)conflict_policy_.completeBatch(state->peerUuid,state->batchId,state->itemCount);
                    }
                    QByteArray done; QDataStream doneStream(&done,QIODevice::WriteOnly); doneStream.setVersion(QDataStream::Qt_6_0);
                    doneStream<<quint8(kTransferAlreadyComplete)<<state->expectedSize;
                    socket->write(done);socket->waitForBytesWritten(kWriteTimeoutMs);socket->disconnectFromHost();return;
                }
                if(same&&!alreadyComplete){
                    state->resumeManifest=*saved;
                    resumeOffset=saved->offset;
                }
            }
            else if(manifestObserved){
                emit error(tr("manifesto de retomada observado não pôde ser aberto com segurança"));
                socket->disconnectFromHost();return;
            }
            if(!authenticatedManifestPresent)removeSecureLeaf(state->partPath);
        }
        // Re-read live authorization after resume state is resolved. This closes
        // the revocation window between the initial gate and acceptance/processing.
        if (!receive_permission_callback_ ||
            !receive_permission_callback_(state->peerUuid)) {
            emit info(tr("Transferência recebida bloqueada: permissão não concedida."));
            emit fileRejected({}, {});
            socket->write(QByteArray(1, kTransferRejected));
            socket->waitForBytesWritten(kWriteTimeoutMs);
            socket->disconnectFromHost();
            return;
        }
        const QString effectReceiveRoot=receiveDirectory();
        const QString effectRelativeParent=QFileInfo(state->fileName).path();
        const QString effectDestinationParent=effectRelativeParent=="."?effectReceiveRoot:
            QDir(effectReceiveRoot).filePath(effectRelativeParent);
        if(!ensureReceiveDirectory(effectReceiveRoot)||!ensureReceiveDirectory(effectDestinationParent)){
            emit error(tr("a cadeia de diretórios de destino contém link, junction ou redirecionamento"));
            socket->disconnectFromHost();return;
        }
        if(state->version>=4 && QFileInfo::exists(requestedPath)){
            if(!state->existingHashReady){
                if(!state->existingHashPending){
                    state->existingHashPending=true;
                    const QPointer<FileTransferService> service(this);const QPointer<QTcpSocket> guardedSocket(socket);
                    const auto cancelled=state->cancelled;
                    QThreadPool::globalInstance()->start([service,guardedSocket,requestedPath,cancelled]{
                        const HashResult result=hashDirectFile(requestedPath,cancelled);
                        if(!service||!guardedSocket||cancelled->load())return;
                        QMetaObject::invokeMethod(service,[service,guardedSocket,result]{
                            if(!service||!guardedSocket)return;
                            auto* current=static_cast<ReceiveState*>(guardedSocket->property("fileTransferState").value<void*>());
                            if(!current||current->cancelled->load())return;
                            current->existingHash=result;current->existingHashReady=true;current->existingHashPending=false;
                            service->readIncoming(guardedSocket);
                        },Qt::QueuedConnection);
                    });
                }
                return;
            }
            const bool existingObjectUnchanged=state->existingHash.lock&&
                openedFileStillMatchesPath(*state->existingHash.lock,requestedPath)&&
                identityForOpenFile(*state->existingHash.lock)==state->existingHash.identity;
            if(!state->existingHash.ok || !existingObjectUnchanged){
                emit error(tr("o destino existente é um link, redirecionamento ou mudou durante a verificação"));
                socket->disconnectFromHost();return;
            }
            // The hash runs asynchronously. Revalidate live authorization after it
            // completes and before deduplication or conflict handling.
            if (!receive_permission_callback_ ||
                !receive_permission_callback_(state->peerUuid)) {
                emit info(tr("Transferência recebida bloqueada: permissão não concedida."));
                emit fileRejected({}, {});
                socket->write(QByteArray(1, kTransferRejected));
                socket->waitForBytesWritten(kWriteTimeoutMs);
                socket->disconnectFromHost();
                return;
            }
            const bool duplicate=state->existingHash.size==state->expectedSize&&
                FileTransferResume::constantTimeEqual(state->existingHash.digest,state->expectedSha256);
            if(duplicate){
                state->existingHash.lock.reset();
                conflict_policy_.recordNonConflict({state->peerUuid,state->batchId,state->transferId,state->fileName,requestedPath,state->itemIndex,state->itemCount});
                if(state->itemIndex+1==state->itemCount)conflict_policy_.completeBatch(state->peerUuid,state->batchId,state->itemCount);
                QByteArray done;QDataStream stream(&done,QIODevice::WriteOnly);stream.setVersion(QDataStream::Qt_6_0);
                stream<<quint8(kTransferDeduplicated)<<state->expectedSize;
                socket->write(done);socket->waitForBytesWritten(kWriteTimeoutMs);socket->disconnectFromHost();return;
            }
            const ConflictRequest request{state->peerUuid,state->batchId,state->transferId,state->fileName,requestedPath,state->itemIndex,state->itemCount};
            const ConflictAction resolvedAction = conflict_policy_.resolve(request, conflict_callback_);
            auto* liveState = static_cast<ReceiveState*>(
                socket->property("fileTransferState").value<void*>());
            if (liveState != state || liveState == nullptr ||
                liveState->cancelled->load() ||
                socket->state() == QAbstractSocket::UnconnectedState) {
                return;
            }
            state = liveState;
            state->conflictAction = resolvedAction;
            if(state->conflictAction==ConflictAction::Replace)state->authorizedDestinationIdentity=state->existingHash.identity;
            if(state->conflictAction==ConflictAction::Skip){
                state->existingHash.lock.reset();
                if(state->itemIndex+1==state->itemCount)conflict_policy_.completeBatch(state->peerUuid,state->batchId,state->itemCount);
                QByteArray done;QDataStream stream(&done,QIODevice::WriteOnly);stream.setVersion(QDataStream::Qt_6_0);
                stream<<quint8(kTransferSkipped)<<state->expectedSize;
                socket->write(done);socket->waitForBytesWritten(kWriteTimeoutMs);socket->disconnectFromHost();return;
            }
            if(state->conflictAction==ConflictAction::Rename)state->existingHash.lock.reset();
        }
        else if(state->version>=4){
            conflict_policy_.recordNonConflict({state->peerUuid,state->batchId,state->transferId,state->fileName,requestedPath,state->itemIndex,state->itemCount});
        }
        if (resumeOffset==0 && incoming_file_callback_ && !incoming_file_callback_(displayName, state->expectedSize, peerAddress, state->peerUuid)) {
            emit info(tr("Transferência recebida bloqueada: permissão não concedida."));
            emit fileRejected({}, {});
            socket->write(QByteArray(1, kTransferRejected));
            socket->waitForBytesWritten(kWriteTimeoutMs);
            socket->disconnectFromHost();
            return;
        }

        state->destinationPath = state->version>=4 && state->conflictAction==ConflictAction::Replace
            ? requestedPath : uniqueDestinationPath(state->fileName);
        state->file = new QFile(state->version>=3?state->partPath:state->destinationPath);
        const bool appendPartial=state->version>=3&&resumeOffset>0;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
        if(state->version>=3&&atomic_publish_test_hooks_.phase)
            atomic_publish_test_hooks_.phase(AtomicPublishPhase::BeforePartialOpen,state->partPath);
#endif
        const bool opened=state->version>=3?openSecurePartial(*state->file,state->partPath,appendPartial,
                                                               &state->partialDirectoryChain
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                                                               ,&atomic_publish_test_hooks_
#endif
                                                               )
                                           :state->file->open(QIODevice::WriteOnly);
        if (!opened) {
            emit error(tr("could not create received file: %1").arg(state->destinationPath));
            socket->disconnectFromHost();
            return;
        }
        if(state->version>=3&&resumeOffset>0){
            quint64 prefixRemaining=resumeOffset;
            bool prefixValid=state->resumeManifest.has_value()&&
                quint64(state->file->size())==resumeOffset&&state->file->seek(0);
            while(prefixValid&&prefixRemaining>0){
                const qint64 wanted=qint64(std::min<quint64>(prefixRemaining,quint64(kChunkSize)));
                const QByteArray chunk=state->file->read(wanted);
                if(chunk.size()!=wanted){prefixValid=false;break;}
                state->hash.addData(chunk);
                prefixRemaining-=quint64(chunk.size());
            }
            prefixValid=prefixValid&&FileTransferResume::constantTimeEqual(
                state->hash.result(),state->resumeManifest->prefixSha256)&&
                state->file->seek(qint64(resumeOffset));
            if(!prefixValid){
                emit error(tr("arquivo parcial aberto não corresponde ao manifesto autenticado"));
                state->file->close();socket->disconnectFromHost();return;
            }
        }
        if(state->version>=3&&!authenticatedManifestPresent){
            FileTransferResume::Manifest initial{state->transferId,state->peerUuid,
                state->itemIndex,state->fileName,state->expectedSize,state->expectedSha256,
                resumeOffset,resumeOffset>0?state->hash.result():QByteArray(),
                QDateTime::currentDateTimeUtc()};
            QString initialError;
            if(!state->file->flush())initialError=tr("não foi possível confirmar o arquivo parcial inicial");
            const QByteArray encoded=initialError.isEmpty()
                ?FileTransferResume::encodeManifest(initial,state->manifestKey,&initialError)
                :QByteArray();
            if(!initialError.isEmpty()||
               !persistManifest(state->manifestPath,encoded,initial,&initialError)){
                emit error(initialError.isEmpty()
                    ?tr("não foi possível criar o manifesto inicial") : initialError);
                state->file->close();removeSecureLeaf(state->partPath);
                socket->disconnectFromHost();return;
            }
            authenticatedManifestPresent=true;
        }
        QByteArray reply; QDataStream replyStream(&reply,QIODevice::WriteOnly); replyStream.setVersion(QDataStream::Qt_6_0);
        replyStream << quint8(kTransferAccepted); if(state->version>=3) replyStream << resumeOffset;
        if(socket->write(reply)!=reply.size() || !socket->waitForBytesWritten(kWriteTimeoutMs)){
            state->file->close(); socket->disconnectFromHost(); return;
        }

        state->receivedSize = resumeOffset;
        state->lastCheckpointSize = resumeOffset;
        state->headerRead = true;
        emit info(tr("receiving file %1").arg(displayName));
        emit receivingStarted(displayName, state->expectedSize);
    }

    const QByteArray data = socket->readAll();
    if (!data.isEmpty() && state->file != nullptr) {
        const quint64 remaining=state->expectedSize-state->receivedSize;
        if(quint64(data.size())>remaining || state->file->write(data)!=data.size()){
            emit error(tr("fluxo de transferência excedeu o tamanho esperado ou não pôde ser gravado"));
            if(state->version>=3){state->file->close();removeSecureLeaf(state->partPath);removeSecureLeaf(state->manifestPath);}
            socket->disconnectFromHost(); return;
        }
        state->hash.addData(data);
        state->receivedSize += static_cast<quint64>(data.size());
        if(state->version>=3&&state->receivedSize<=state->expectedSize&&
           (state->receivedSize==state->expectedSize||
            state->receivedSize-state->lastCheckpointSize>=kProgressStepBytes)){
            FileTransferResume::Manifest m{state->transferId,state->peerUuid,state->itemIndex,state->fileName,state->expectedSize,state->expectedSha256,
                state->receivedSize,state->hash.result(),QDateTime::currentDateTimeUtc()};
            QString checkpointError;
            if(!state->file->flush())checkpointError=tr("não foi possível confirmar o arquivo parcial");
            const QByteArray encoded=checkpointError.isEmpty()?FileTransferResume::encodeManifest(m,state->manifestKey,&checkpointError):QByteArray();
            if(!checkpointError.isEmpty() ||
               !persistManifest(state->manifestPath,encoded,m,&checkpointError)){
                emit error(checkpointError.isEmpty()?tr("não foi possível salvar o ponto de retomada"):checkpointError);
                state->file->close();
                socket->disconnectFromHost(); return;
            }
            state->lastCheckpointSize=state->receivedSize;
        }
        if (state->receivedSize == state->expectedSize ||
            state->receivedSize - state->lastProgressSize >= kProgressStepBytes) {
            state->lastProgressSize = state->receivedSize;
            emit receivingProgress(QFileInfo(state->fileName).fileName(), state->receivedSize, state->expectedSize);
        }
    }

    if (state->headerRead && state->receivedSize >= state->expectedSize) {
        const bool sourceFlushed=state->version<3||state->file->flush();
        if(state->version<3)state->file->close();
        const bool verified = sourceFlushed&&(state->expectedSha256.isEmpty() ||
            FileTransferResume::constantTimeEqual(state->hash.result(),state->expectedSha256));
        if (verified) {
            if(state->version>=3){
                FileTransferResume::Manifest completion{state->transferId,state->peerUuid,state->itemIndex,state->fileName,state->expectedSize,
                    state->expectedSha256,state->expectedSize,state->expectedSha256,QDateTime::currentDateTimeUtc()};
                completion.publishedPath=state->destinationPath;
                QString completionError;
                QByteArray encoded=FileTransferResume::encodeManifest(completion,state->manifestKey,&completionError);
                if(!completionError.isEmpty()||
                   !persistManifest(state->manifestPath,encoded,completion,&completionError)){
                    emit error(completionError.isEmpty()?tr("não foi possível preparar a confirmação da transferência"):completionError);
                    state->file->close();
                    socket->write(QByteArray(1,kTransferRejected));socket->waitForBytesWritten(kWriteTimeoutMs);socket->disconnectFromHost();return;
                }
                const bool replacing=state->version>=4&&state->conflictAction==ConflictAction::Replace;
                const QString publishParent=QFileInfo(state->destinationPath).absolutePath();
                const bool safeParent=ensureReceiveDirectory(receiveDirectory())&&
                    ensureReceiveDirectory(publishParent);
                const bool sameAuthorizedObject=!replacing ||
                    (state->authorizedDestinationIdentity.valid&&state->existingHash.lock&&
                     openedFileStillMatchesPath(*state->existingHash.lock,state->destinationPath)&&
                     identityForOpenFile(*state->existingHash.lock)==state->authorizedDestinationIdentity);
                QFile* authorizedExisting=replacing&&state->existingHash.deleteAccess
                    ? state->existingHash.lock.get():nullptr;
                std::shared_ptr<PinnedDirectoryChain> publicationChain;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                if(atomic_publish_test_hooks_.phase)
                    atomic_publish_test_hooks_.phase(AtomicPublishPhase::BeforePublicationChain,
                                                     state->destinationPath);
#endif
#ifdef Q_OS_WIN
                publicationChain=pinDescendantParentChain(state->destinationPath,
                    receiveDirectory(),state->partialDirectoryChain);
#endif
                QString preparedRecoveryPath;
                const auto persistRecoveryPreparation=[&](const QString& path){
                    completion.completed=false;completion.recoveryPath=path;
                    completion.updatedAtUtc=QDateTime::currentDateTimeUtc();completionError.clear();
                    encoded=FileTransferResume::encodeManifest(
                        completion,state->manifestKey,&completionError);
                    if(!completionError.isEmpty()||
                       !persistManifest(state->manifestPath,encoded,completion,&completionError))
                        return false;
                    preparedRecoveryPath=path;return true;
                };
                const auto persistRecoveryCommit=[&](const QString& path){
                    completion.completed=true;completion.recoveryPath=path;
                    completion.updatedAtUtc=QDateTime::currentDateTimeUtc();completionError.clear();
                    encoded=FileTransferResume::encodeManifest(
                        completion,state->manifestKey,&completionError);
                    return completionError.isEmpty()&&
                        persistManifest(state->manifestPath,encoded,completion,&completionError);
                };
                QString recoveryPath;
                const bool published=safeParent&&sameAuthorizedObject&&publicationChain&&
                    atomicPublish(*state->file,state->partPath,state->destinationPath,replacing,
                                  authorizedExisting,&recoveryPath,publicationChain,
                                  persistRecoveryPreparation,persistRecoveryCommit
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
                                  ,&atomic_publish_test_hooks_
#endif
                                  );
                state->file->close();
                state->existingHash.lock.reset();
                if(!published){
                    QString terminalRecovery=recoveryPath;
                    if(terminalRecovery.isEmpty()&&!preparedRecoveryPath.isEmpty()){
                        completion.completed=false;completion.recoveryPath.clear();
                        completion.updatedAtUtc=QDateTime::currentDateTimeUtc();
                        completionError.clear();
                        encoded=FileTransferResume::encodeManifest(
                            completion,state->manifestKey,&completionError);
                        if(!completionError.isEmpty()||
                           !persistManifest(state->manifestPath,encoded,completion,&completionError)){
                            terminalRecovery=preparedRecoveryPath;
                            emit error(tr("o journal de recuperação permaneceu ativo"));
                        }
                    }
                    const QString terminalName=QFileInfo(state->fileName).fileName();
                    emit publicationCompleted(terminalName,
                        {terminalRecovery.isEmpty()?PublicationStatus::Unchanged:PublicationStatus::RecoveryRequired,
                         state->destinationPath,terminalRecovery,state->peerUuid,state->transferId});
                    emit fileRejected(terminalName,socket->peerAddress().toString(),state->transferId);
                    emit error(terminalRecovery.isEmpty()
                        ? tr("não foi possível publicar atomicamente o arquivo recebido sem alterar o destino autorizado")
                        : tr("não foi possível publicar o arquivo; o original foi preservado para recuperação em %1")
                              .arg(terminalRecovery));
                    socket->write(QByteArray(1,kTransferRejected));socket->waitForBytesWritten(kWriteTimeoutMs);socket->disconnectFromHost(); return;
                }
                completion.completed=true;completion.recoveryPath=recoveryPath;
                completion.updatedAtUtc=QDateTime::currentDateTimeUtc();completionError.clear();
                if(state->version>=4&&state->itemIndex+1==state->itemCount)
                    conflict_policy_.completeBatch(state->peerUuid,state->batchId,state->itemCount);
                encoded=FileTransferResume::encodeManifest(completion,state->manifestKey,&completionError);
                if(!completionError.isEmpty()||
                   !persistManifest(state->manifestPath,encoded,completion,&completionError))
                    emit error(tr("a confirmação durável será recuperada na próxima conexão"));
                if(!recoveryPath.isEmpty())
                    emit error(tr("o arquivo novo foi publicado, mas o original precisou ser preservado em %1")
                                   .arg(recoveryPath));
                emit publicationCompleted(QFileInfo(state->fileName).fileName(),
                    {recoveryPath.isEmpty()?PublicationStatus::Committed:PublicationStatus::CommittedWithRecovery,
                     state->destinationPath,recoveryPath,state->peerUuid,state->transferId});
            }
            else {
                emit publicationCompleted(QFileInfo(state->fileName).fileName(),
                    {PublicationStatus::Committed,state->destinationPath,{},state->peerUuid,state->transferId});
            }
            emit info(tr("received file %1 in %2 (SHA-256 verified)").arg(QFileInfo(state->fileName).fileName(), receiveDirectory()));
        }
        else {
            if(state->version>=3){state->file->close();removeSecureLeaf(state->partPath);removeSecureLeaf(state->manifestPath);}
            emit error(tr("received file %1 but SHA-256 verification failed").arg(QFileInfo(state->fileName).fileName()));
        }
        emit fileReceived(QFileInfo(state->fileName).fileName(),state->destinationPath,verified,
                          state->peerUuid,state->transferId);
        const QByteArray finalStatus(1,verified?kTransferAccepted:kTransferRejected);
        if(socket->write(finalStatus)!=finalStatus.size()||!socket->waitForBytesWritten(kWriteTimeoutMs))
            emit error(tr("não foi possível entregar a confirmação final da transferência"));
        socket->disconnectFromHost();
    }
}

bool FileTransferService::sendFiles(const QString& host,
                                    quint16 port,
                                    const QStringList& files,
                                    QString* errorMessage,
                                    ProgressCallback progressCallback,
                                    CancelCallback cancelCallback,
                                    const QString& pairingCode,
                                    const QUuid& localUuid,
                                    const QByteArray& preSharedKey,
                                    bool resumeEnabled,
                                    SendFailure* failureKind,
                                    quint64 bandwidthBytesPerSecond,
                                    bool conflictProtocolEnabled,
                                    TransferSummary* summary)
{
    QList<TransferItem> items;
    for (const QString& path : files) {
        items.append({path, QFileInfo(path).fileName()});
    }

    return sendItems(host,port,items,errorMessage,progressCallback,cancelCallback,pairingCode,localUuid,preSharedKey,resumeEnabled,failureKind,bandwidthBytesPerSecond,conflictProtocolEnabled,summary);
}

bool FileTransferService::sendItems(const QString& host,
                                    quint16 port,
                                    const QList<TransferItem>& items,
                                    QString* errorMessage,
                                    ProgressCallback progressCallback,
                                    CancelCallback cancelCallback,
                                    const QString& pairingCode,
                                    const QUuid& localUuid,
                                    const QByteArray& suppliedPreSharedKey,
                                    bool resumeEnabled,
                                    SendFailure* failureKind,
                                    quint64 bandwidthBytesPerSecond,
                                    bool conflictProtocolEnabled,
                                    TransferSummary* summary)
{
    (void)resumeEnabled;
    (void)conflictProtocolEnabled;
    if(summary)*summary={};
    if(failureKind)*failureKind=SendFailure::Terminal;
    if ((!localUuid.isNull() || !suppliedPreSharedKey.isEmpty()) &&
        (localUuid.isNull() || suppliedPreSharedKey.size()!=32)) {
        if(errorMessage)*errorMessage=tr("invalid paired-device transfer credentials");
        return false;
    }
    BandwidthThrottle throttle(PerformancePolicy(1, bandwidthBytesPerSecond).bandwidthBytesPerSecond());
    const QByteArray batchId=QUuid::createUuid().toRfc4122();
    quint32 itemIndex=0;
    for (const TransferItem& item : items) {
        const QByteArray transferId=item.transferId.size()==16?item.transferId:QUuid::createUuid().toRfc4122();
        const bool persistedBatch=item.batchId.size()==16&&item.batchCount>0&&item.batchIndex<item.batchCount;
        const QByteArray wireBatchId=persistedBatch?item.batchId:batchId;
        const quint32 wireItemIndex=persistedBatch?item.batchIndex:itemIndex;
        const quint32 wireItemCount=persistedBatch?item.batchCount:quint32(items.size());
        if (cancelCallback && cancelCallback()) {
            if (errorMessage != nullptr) {
                *errorMessage = tr("file transfer cancelled");
            }
            return false;
        }

        if(!isDirectCanonicalPath(item.sourcePath)){
            if(errorMessage)*errorMessage=tr("links and redirected paths are not allowed: %1").arg(item.sourcePath);
            return false;
        }
        QFile file(item.sourcePath);
        const QFileInfo info(file);
        const QString displayName = item.relativePath.isEmpty() ? info.fileName() : QDir::cleanPath(item.relativePath);

        if (!info.exists() || !info.isFile()) {
            if (errorMessage != nullptr) {
                *errorMessage = tr("not a valid file: %1").arg(item.sourcePath);
            }
            return false;
        }

        if (!file.open(QIODevice::ReadOnly)) {
            if (errorMessage != nullptr) {
                *errorMessage = tr("could not open file: %1").arg(item.sourcePath);
            }
            return false;
        }
        if(!openedFileStillMatchesPath(file,item.sourcePath)){
            if(errorMessage)*errorMessage=tr("file changed or resolves through a link: %1").arg(item.sourcePath);
            return false;
        }

        const qint64 sourceSize=file.size();
        const QByteArray sha256 = calculateSha256(file, cancelCallback);
        if (sha256.isEmpty() && file.size() > 0) {
            if (errorMessage != nullptr) {
                *errorMessage = tr("file transfer cancelled");
            }
            return false;
        }
        if(file.size()!=sourceSize || !openedFileStillMatchesPath(file,item.sourcePath)){
            if(errorMessage)*errorMessage=tr("o arquivo de origem mudou durante a preparação: %1").arg(item.sourcePath);
            return false;
        }

        const bool useDeviceKey=!localUuid.isNull()&&suppliedPreSharedKey.size()==32;
        QString addressText = host.trimmed();
        if (addressText.startsWith('[') && addressText.endsWith(']'))
            addressText = addressText.mid(1, addressText.size() - 2);
        QHostAddress destinationAddress;
        const auto authenticatedEndpoint = destinationAddress.setAddress(addressText)
            ? ProtocolSecurityPolicy::canonicalEndpoint(destinationAddress, port)
            : ProtocolSecurityPolicy::canonicalEndpoint(
                  host + QStringLiteral(":") + QString::number(port));
        if (useDeviceKey && !authenticatedEndpoint) {
            if (errorMessage) *errorMessage=tr("security authorization endpoint is invalid");
            return false;
        }
        const quint16 wireVersion=useDeviceKey?quint16(5):quint16(2);
        QByteArray preSharedKey=useDeviceKey?suppliedPreSharedKey:pairingKeyForCode(pairingCode);
        preSharedKey.detach();
        const auto keyGuard=qScopeGuard([&preSharedKey]{cleanse(preSharedKey);});
        QSslSocket socket;
        if (!preSharedKey.isEmpty()) {
            connect(&socket, &QSslSocket::preSharedKeyAuthenticationRequired, &socket,
                    [&preSharedKey,localUuid,useDeviceKey](QSslPreSharedKeyAuthenticator* authenticator) {
                        authenticator->setIdentity(useDeviceKey?deviceIdentity(localUuid):kLegacyTlsPskIdentity);
                        authenticator->setPreSharedKey(preSharedKey);
                    });
            if (!configureTlsPsk(&socket)) {
                if (errorMessage != nullptr) {
                    *errorMessage = tr("TLS-PSK is unavailable in this Qt/OpenSSL installation");
                }
                return false;
            }
            socket.connectToHostEncrypted(host, port);
            const auto encrypted = waitForSocketCancellable(
                socket, kConnectTimeoutMs,
                [&socket] { return socket.isEncrypted(); },
                [&socket](int timeout) { socket.waitForEncrypted(timeout); },
                cancelCallback);
            if (encrypted != SocketWaitResult::Ready) {
                if (errorMessage != nullptr) {
                    *errorMessage = encrypted == SocketWaitResult::Cancelled
                        ? tr("file transfer cancelled")
                        : tr("TLS-PSK authentication failed for %1:%2 - %3")
                              .arg(host).arg(port).arg(socket.errorString());
                }
                return false;
            }
        }
        else {
            socket.connectToHost(host, port);
            const auto connected = waitForSocketCancellable(
                socket, kConnectTimeoutMs,
                [&socket] { return socket.state() == QAbstractSocket::ConnectedState; },
                [&socket](int timeout) { socket.waitForConnected(timeout); },
                cancelCallback);
            if (connected != SocketWaitResult::Ready) {
                if (connected == SocketWaitResult::Cancelled) {
                    if (errorMessage) *errorMessage = tr("file transfer cancelled");
                    return false;
                }
                if(failureKind)*failureKind=SendFailure::Transient;
                if (errorMessage != nullptr) {
                    *errorMessage = tr("could not connect to %1:%2 - %3").arg(host).arg(port).arg(socket.errorString());
                }
                return false;
            }
        }

        QDataStream out(&socket);
        out.setVersion(QDataStream::Qt_6_0);
        out << kMagic << wireVersion;
        if(wireVersion>=3) {
            out << transferId << wireItemIndex;
            if(wireVersion>=4)out << wireBatchId << wireItemCount;
            if(wireVersion>=5) {
                const auto token = ProtocolSecurityPolicy([] { return QDateTime::currentMSecsSinceEpoch(); }).issue(
                    localUuid, localUuid, *authenticatedEndpoint, {"file-transfer:5"}, preSharedKey, 300000);
                if(!token) { if(errorMessage) *errorMessage=tr("security authorization unavailable"); return false; }
                out << *token;
            }
            out << displayName << static_cast<quint64>(file.size()) << sha256;
        }
        else out << displayName << static_cast<quint64>(file.size()) << sha256;
        const auto headerWritten = waitForSocketCancellable(
            socket, kWriteTimeoutMs,
            [&socket] { return socket.bytesToWrite() == 0; },
            [&socket](int timeout) { socket.waitForBytesWritten(timeout); },
            cancelCallback);
        if (headerWritten != SocketWaitResult::Ready) {
            if (headerWritten == SocketWaitResult::Cancelled) {
                if (errorMessage) *errorMessage = tr("file transfer cancelled");
                return false;
            }
            if(failureKind)*failureKind=SendFailure::Transient;
            if (errorMessage != nullptr) {
                *errorMessage = tr("failed while sending %1: %2").arg(displayName, socket.errorString());
            }
            return false;
        }

        const auto responseReady = waitForSocketCancellable(
            socket, kHeaderResponseTimeoutMs,
            [&socket] { return socket.bytesAvailable() > 0; },
            [&socket](int timeout) { socket.waitForReadyRead(timeout); },
            cancelCallback);
        if (responseReady != SocketWaitResult::Ready) {
            if (responseReady == SocketWaitResult::Cancelled) {
                if (errorMessage) *errorMessage = tr("file transfer cancelled");
                return false;
            }
            if(failureKind)*failureKind=SendFailure::Transient;
            if (errorMessage != nullptr) {
                *errorMessage = tr("no response from remote computer for %1: %2").arg(displayName, socket.errorString());
            }
            return false;
        }

        QByteArray response = socket.readAll();
        while (wireVersion >= 3 && response.size() < 9) {
            const auto moreResponse = waitForSocketCancellable(
                socket, 1000,
                [&socket] { return socket.bytesAvailable() > 0; },
                [&socket](int timeout) { socket.waitForReadyRead(timeout); },
                cancelCallback);
            if (moreResponse == SocketWaitResult::Cancelled) {
                if (errorMessage) *errorMessage = tr("file transfer cancelled");
                return false;
            }
            if (moreResponse != SocketWaitResult::Ready) break;
            response += socket.readAll();
        }
        const bool completedWithoutPayload=!response.isEmpty()&&wireVersion>=3&&
            (response.at(0)==kTransferAlreadyComplete || (wireVersion>=4&&
             (response.at(0)==kTransferDeduplicated||response.at(0)==kTransferSkipped)));
        if (response.isEmpty() || (response.at(0) != kTransferAccepted && !completedWithoutPayload)) {
            if (errorMessage != nullptr) {
                *errorMessage = response.isEmpty() || response.at(0) == kTransferRejected
                    ? tr("remote computer rejected file: %1").arg(displayName)
                    : tr("remote computer sent an invalid file transfer response for %1").arg(displayName);
            }
            return false;
        }

        quint64 bytesSent = 0;
        if(wireVersion>=3){
            QDataStream responseStream(response); responseStream.setVersion(QDataStream::Qt_6_0); quint8 status=0; responseStream>>status>>bytesSent;
            const bool noPayload=status==quint8(kTransferAlreadyComplete)||(wireVersion>=4&&
                (status==quint8(kTransferDeduplicated)||status==quint8(kTransferSkipped)));
            if(responseStream.status()!=QDataStream::Ok || (status!=quint8(kTransferAccepted)&&!noPayload) ||
               bytesSent>quint64(file.size()) || (noPayload&&bytesSent!=quint64(file.size())) || !file.seek(qint64(bytesSent))){
                if(errorMessage)*errorMessage=tr("resposta de retomada inválida para %1").arg(displayName); return false;
            }
            if(noPayload){
                if(summary){
                    if(status==quint8(kTransferSkipped))++summary->skipped;
                    else ++summary->deduplicated;
                }
                if(progressCallback)progressCallback(displayName,bytesSent,quint64(file.size()));
                socket.disconnectFromHost();
                (void)waitForSocketCancellable(
                    socket, 1000,
                    [&socket] { return socket.state() == QAbstractSocket::UnconnectedState; },
                    [&socket](int timeout) { socket.waitForDisconnected(timeout); },
                    cancelCallback);
                ++itemIndex;continue;
            }
        }
        quint64 lastProgressSize = 0;
        if (progressCallback) {
            progressCallback(displayName, bytesSent, static_cast<quint64>(file.size()));
        }

        while (!file.atEnd()) {
            if (cancelCallback && cancelCallback()) {
                socket.disconnectFromHost();
                if (errorMessage != nullptr) {
                    *errorMessage = tr("file transfer cancelled");
                }
                return false;
            }

            const QByteArray chunk = file.read(kChunkSize);
            if (!throttle.beforeSend(quint64(chunk.size()), cancelCallback)) {
                socket.disconnectFromHost();
                if (errorMessage) *errorMessage = tr("file transfer cancelled");
                return false;
            }
            socket.write(chunk);
            const auto chunkWritten = waitForSocketCancellable(
                socket, kWriteTimeoutMs,
                [&socket] { return socket.bytesToWrite() == 0; },
                [&socket](int timeout) { socket.waitForBytesWritten(timeout); },
                cancelCallback);
            if (chunkWritten != SocketWaitResult::Ready) {
                if (chunkWritten == SocketWaitResult::Cancelled) {
                    if (errorMessage) *errorMessage = tr("file transfer cancelled");
                    return false;
                }
                if(failureKind)*failureKind=SendFailure::Transient;
                if (errorMessage != nullptr) {
                    *errorMessage = tr("failed while sending %1: %2").arg(displayName, socket.errorString());
                }
                return false;
            }

            bytesSent += static_cast<quint64>(chunk.size());
            if (progressCallback &&
                (bytesSent == static_cast<quint64>(file.size()) ||
                 bytesSent - lastProgressSize >= kProgressStepBytes)) {
                lastProgressSize = bytesSent;
                progressCallback(displayName, bytesSent, static_cast<quint64>(file.size()));
            }
        }

        if(wireVersion>=3){
            const auto integrityReady = waitForSocketCancellable(
                socket, kHeaderResponseTimeoutMs,
                [&socket] { return socket.bytesAvailable() > 0; },
                [&socket](int timeout) { socket.waitForReadyRead(timeout); },
                cancelCallback);
            if (integrityReady != SocketWaitResult::Ready) {
                if (integrityReady == SocketWaitResult::Cancelled) {
                    if (errorMessage) *errorMessage = tr("file transfer cancelled");
                    return false;
                }
                if(failureKind)*failureKind=SendFailure::Transient;
                if(errorMessage)*errorMessage=tr("o outro computador não confirmou a integridade de %1").arg(displayName);
                socket.disconnectFromHost(); return false;
            }
            if(socket.read(1)!=QByteArray(1,kTransferAccepted)){
                if(errorMessage)*errorMessage=tr("o outro computador rejeitou a integridade de %1").arg(displayName);
                socket.disconnectFromHost(); return false;
            }
        }
        socket.disconnectFromHost();
        (void)waitForSocketCancellable(
            socket, 1000,
            [&socket] { return socket.state() == QAbstractSocket::UnconnectedState; },
            [&socket](int timeout) { socket.waitForDisconnected(timeout); },
            cancelCallback);
        if(summary)++summary->transferred;
        ++itemIndex;
    }

    if(failureKind)*failureKind=SendFailure::None;
    return true;
}
