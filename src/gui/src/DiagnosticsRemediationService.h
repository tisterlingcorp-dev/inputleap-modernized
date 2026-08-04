#pragma once
#include <QObject>
#include <QFlags>
#include <QList>
#include <QString>
#include <QUrl>
#include <functional>
#include <memory>

enum class FirewallProfile : quint32 { None=0, Domain=1, Private=2, Public=4 };
Q_DECLARE_FLAGS(FirewallProfiles, FirewallProfile)
Q_DECLARE_OPERATORS_FOR_FLAGS(FirewallProfiles)
struct FirewallRuleSpec { QString executablePath; QList<quint16> ports; FirewallProfiles profiles; };
struct FirewallRuleSetSpec { QList<FirewallRuleSpec> rules; };
struct FirewallObservedRule {
    QString name; QString executablePath; QList<quint16> localPorts; FirewallProfiles profiles;
    bool enabled=false; bool inbound=false; bool allow=false; int protocol=0;
};
enum class FirewallDetectionStatus { Present, Missing, Unknown, AccessDenied };
struct FirewallDetection { FirewallDetectionStatus status=FirewallDetectionStatus::Unknown; QString technical; };
struct FirewallValidation { bool ok=false; QString reason; };
class FirewallRemediationPolicy {
public:
    static FirewallValidation validate(const FirewallRuleSpec&);
    static FirewallValidation validate(const FirewallRuleSetSpec&);
    static FirewallDetection classify(const FirewallRuleSetSpec&, const QList<FirewallObservedRule>&);
    static FirewallDetection accessFailure(bool, const QString&);
    static QString canonicalForComparison(const QString&);
};
enum class RemediationLaunchResult { Started, Cancelled, Failed };
class DiagnosticsRemediationAdapter {
public:
    using DetectionCallback=std::function<void(FirewallDetection)>;
    using LaunchCallback=std::function<void(RemediationLaunchResult)>;
    virtual ~DiagnosticsRemediationAdapter()=default;
    virtual void detectFirewall(const FirewallRuleSetSpec&, DetectionCallback)=0;
    virtual void launchElevatedFirewallHelper(const FirewallRuleSetSpec&, LaunchCallback)=0;
};
class DiagnosticsRemediationService final : public QObject {
    Q_OBJECT
public:
    explicit DiagnosticsRemediationService(DiagnosticsRemediationAdapter* adapter=nullptr, QObject* parent=nullptr);
    ~DiagnosticsRemediationService() override;
    void inspect(const FirewallRuleSetSpec&);
    bool canRemediateFirewall() const;
    void remediateFirewall(bool);
    FirewallDetection lastDetection() const { return detection_; }
signals:
    void firewallInspected(const FirewallDetection&);
    void firewallRemediationCancelled();
    void firewallRemediationFailed(const QString&);
    void firewallVerified();
private:
    class WindowsAdapter;
    std::unique_ptr<DiagnosticsRemediationAdapter> owned_;
    DiagnosticsRemediationAdapter* adapter_=nullptr;
    FirewallRuleSetSpec spec_;
    FirewallDetection detection_;
    quint64 generation_=0;
    bool busy_=false;
};
class DiagnosticsRemediationActions {
public:
    using OpenUrl=std::function<bool(const QUrl&)>; using OpenSettings=std::function<void()>;
    DiagnosticsRemediationActions(OpenUrl,OpenSettings);
    bool openReceiveFolder(const QString&) const; bool openSettings() const;
private: OpenUrl openUrl_; OpenSettings openSettings_;
};
Q_DECLARE_METATYPE(FirewallDetection)
