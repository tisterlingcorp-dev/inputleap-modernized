#pragma once
#include <QObject>
#include <QStringList>
#include <QUuid>
#include <functional>
#include <memory>

Q_NAMESPACE
enum class DiagnosticSeverity { Ok, Warning, Error }; Q_ENUM_NS(DiagnosticSeverity)
struct DiagnosticCheck { QString id; DiagnosticSeverity severity=DiagnosticSeverity::Ok; QString simple; QString technical; };
Q_DECLARE_METATYPE(DiagnosticCheck)
struct DiagnosticsReport { quint64 runId=0; DiagnosticSeverity overall=DiagnosticSeverity::Ok; QList<DiagnosticCheck> checks; QString toPlainText(bool includeTechnical=false) const; };
Q_DECLARE_METATYPE(DiagnosticsReport)
struct DiagnosticsInput {
    QUuid deviceUuid; bool deviceSelected=false; QString endpoint; quint16 controlPort=0; quint16 transferPort=0;
    bool discovered=false; bool compatible=false; QString version; bool fileTransferCapability=false; bool tlsPskCapability=false;
    bool hasPairSessionKey=false; QString receiveFolder; int networkTimeoutMs=2500; int folderTimeoutMs=3000;
};
class DiagnosticsAdapter {
public:
    enum class TcpState { Reachable, Refused, TimedOut, Failed };
    struct TcpProbe { TcpState state=TcpState::Failed; QString technical; };
    struct ResolveProbe { QStringList addresses; QString technical; };
    struct FolderProbe { bool exists=false; bool writable=false; bool permissionProbeSucceeded=false; QString technical; };
    using TcpCallback=std::function<void(TcpProbe)>; using ResolveCallback=std::function<void(ResolveProbe)>; using FolderCallback=std::function<void(FolderProbe)>;
    virtual ~DiagnosticsAdapter()=default;
    virtual void resolveHost(const QString& host, ResolveCallback callback)=0;
    virtual void probeTcp(const QString& host, quint16 port, int timeoutMs, TcpCallback callback)=0;
    virtual void probeFolder(const QString& path, FolderCallback callback)=0;
    virtual void cancelAll()=0;
};
class DiagnosticsService final : public QObject {
    Q_OBJECT
public: explicit DiagnosticsService(DiagnosticsAdapter* adapter=nullptr,QObject* parent=nullptr); ~DiagnosticsService() override; quint64 start(const DiagnosticsInput&); void cancel();
signals: void completed(quint64 runId,const DiagnosticsReport& report);
private:
    class RealAdapter; void acceptResolve(quint64,DiagnosticsAdapter::ResolveProbe); void startTcp(quint64,const QString&); void acceptTcp(quint64,const QString&,DiagnosticsAdapter::TcpProbe); void acceptFolder(quint64,DiagnosticsAdapter::FolderProbe); void completeOne(quint64); void finalize(quint64);
    std::unique_ptr<DiagnosticsAdapter> ownedAdapter_; DiagnosticsAdapter* adapter_=nullptr; quint64 generation_=0; DiagnosticsInput input_; QList<DiagnosticCheck> checks_; int pending_=0; bool resolvePending_=false; bool folderPending_=false;
};
