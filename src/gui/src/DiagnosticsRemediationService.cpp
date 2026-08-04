#include "DiagnosticsRemediationService.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QMetaObject>
#include <QPointer>
#include <QThreadPool>
#include <QUrl>
#include <algorithm>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <netfw.h>
#include <shellapi.h>
#endif
namespace{
bool samePorts(QList<quint16>a,QList<quint16>b){std::sort(a.begin(),a.end());std::sort(b.begin(),b.end());return a==b;}
bool unsafe(const QString&s){return s.contains('\r')||s.contains('\n')||s.contains(QChar::Null);}
#ifdef Q_OS_WIN
QString fromBstr(BSTR s){return s?QString::fromWCharArray(s,SysStringLen(s)):QString();}
QList<quint16> ports(const QString&t,bool&ok){QList<quint16>o;ok=true;for(const auto&v:t.split(',',Qt::SkipEmptyParts)){bool nOk=false;int n=v.trimmed().toInt(&nOk);if(!nOk||n<1||n>65535){ok=false;return{};}o<<quint16(n);}return o;}
FirewallProfiles profiles(long p){FirewallProfiles r;if(p&NET_FW_PROFILE2_DOMAIN)r|=FirewallProfile::Domain;if(p&NET_FW_PROFILE2_PRIVATE)r|=FirewallProfile::Private;if(p&NET_FW_PROFILE2_PUBLIC)r|=FirewallProfile::Public;return r;}
FirewallDetection comFailure(HRESULT hr,const QString&where){return FirewallRemediationPolicy::accessFailure(hr==E_ACCESSDENIED,QStringLiteral("%1 (0x%2)").arg(where).arg(quint32(hr),8,16,QChar('0')));}
FirewallDetection detectCom(const FirewallRuleSetSpec&spec){
 HRESULT ci=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);bool uninit=SUCCEEDED(ci);if(FAILED(ci)&&ci!=RPC_E_CHANGED_MODE)return comFailure(ci,"Falha ao inicializar COM");
 INetFwPolicy2*p=nullptr;HRESULT hr=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),(void**)&p);if(FAILED(hr)){if(uninit)CoUninitialize();return comFailure(hr,"Falha ao abrir firewall");}
 INetFwRules*rs=nullptr;hr=p->get_Rules(&rs);p->Release();if(FAILED(hr)){if(uninit)CoUninitialize();return comFailure(hr,"Falha ao consultar regras");}
 IUnknown*u=nullptr;IEnumVARIANT*e=nullptr;hr=rs->get__NewEnum(&u);if(SUCCEEDED(hr))hr=u->QueryInterface(IID_IEnumVARIANT,(void**)&e);if(u)u->Release();QList<FirewallObservedRule>seen;
 while(SUCCEEDED(hr)){VARIANT v;VariantInit(&v);ULONG fetched=0;HRESULT next=e->Next(1,&v,&fetched);if(next==S_FALSE){VariantClear(&v);break;}if(next!=S_OK){hr=next;VariantClear(&v);break;}if(v.vt==VT_DISPATCH){INetFwRule*r=nullptr;hr=v.pdispVal->QueryInterface(__uuidof(INetFwRule),(void**)&r);if(SUCCEEDED(hr)){BSTR name=nullptr,app=nullptr,local=nullptr;VARIANT_BOOL enabled=VARIANT_FALSE;NET_FW_RULE_DIRECTION direction=NET_FW_RULE_DIR_MAX;NET_FW_ACTION action=NET_FW_ACTION_MAX;long protocol=0,profileBits=0;
  hr=r->get_Name(&name);if(SUCCEEDED(hr))hr=r->get_ApplicationName(&app);if(SUCCEEDED(hr))hr=r->get_LocalPorts(&local);if(SUCCEEDED(hr))hr=r->get_Enabled(&enabled);if(SUCCEEDED(hr))hr=r->get_Direction(&direction);if(SUCCEEDED(hr))hr=r->get_Action(&action);if(SUCCEEDED(hr))hr=r->get_Protocol(&protocol);if(SUCCEEDED(hr))hr=r->get_Profiles(&profileBits);bool parseOk=false;auto parsed=ports(fromBstr(local),parseOk);if(SUCCEEDED(hr)&&!parseOk)hr=E_FAIL;if(SUCCEEDED(hr))seen<<FirewallObservedRule{fromBstr(name),fromBstr(app),parsed,profiles(profileBits),enabled==VARIANT_TRUE,direction==NET_FW_RULE_DIR_IN,action==NET_FW_ACTION_ALLOW,int(protocol)};SysFreeString(name);SysFreeString(app);SysFreeString(local);r->Release();}}
 VariantClear(&v);if(FAILED(hr))break;}
 if(e)e->Release();rs->Release();if(uninit)CoUninitialize();if(FAILED(hr))return comFailure(hr,"Falha ao enumerar propriedade de regra");return FirewallRemediationPolicy::classify(spec,seen);
}
QString quote(const QString&x){QString o="\"";int sl=0;for(QChar c:x){if(c=='\\'){++sl;continue;}if(c=='\"'){o+=QString(sl*2+1,'\\');o+=c;sl=0;continue;}o+=QString(sl,'\\');sl=0;o+=c;}o+=QString(sl*2,'\\');return o+'\"';}
#endif
}
QString FirewallRemediationPolicy::canonicalForComparison(const QString&p){QFileInfo f(p);QString v=f.canonicalFilePath();if(v.isEmpty())v=QDir::cleanPath(f.absoluteFilePath());return QDir::toNativeSeparators(v).toCaseFolded();}
FirewallValidation FirewallRemediationPolicy::validate(const FirewallRuleSpec&s){QFileInfo f(s.executablePath);if(s.executablePath.trimmed().isEmpty()||unsafe(s.executablePath)||!f.isAbsolute()||!f.isFile()||f.canonicalFilePath().isEmpty()||f.suffix().compare("exe",Qt::CaseInsensitive))return{false,"Caminho inválido."};if(s.ports.isEmpty())return{false,"Portas vazias."};for(auto p:s.ports)if(!p)return{false,"Porta inválida."};auto allowed=FirewallProfile::Domain|FirewallProfile::Private;if(s.profiles!=allowed)return{false,"Perfis devem ser Domínio e Privado."};return{true,{}};}
FirewallValidation FirewallRemediationPolicy::validate(const FirewallRuleSetSpec&s){if(s.rules.isEmpty()||s.rules.size()>2)return{false,"Conjunto deve conter uma ou duas regras."};QList<QString>paths;for(const auto&r:s.rules){auto v=validate(r);if(!v.ok)return v;auto p=canonicalForComparison(r.executablePath);if(paths.contains(p))return{false,"Executáveis duplicados."};paths<<p;}return{true,{}};}
FirewallDetection FirewallRemediationPolicy::classify(const FirewallRuleSetSpec&s,const QList<FirewallObservedRule>&rules){if(!validate(s).ok)return{FirewallDetectionStatus::Unknown,"Especificação inválida."};for(const auto&wanted:s.rules){bool found=false;for(const auto&r:rules)if(r.enabled&&r.inbound&&r.allow&&r.protocol==6&&canonicalForComparison(r.executablePath)==canonicalForComparison(wanted.executablePath)&&samePorts(r.localPorts,wanted.ports)&&r.profiles==wanted.profiles){found=true;break;}if(!found)return{FirewallDetectionStatus::Missing,"Uma ou mais regras efetivas estão ausentes."};}return{FirewallDetectionStatus::Present,"Todas as regras TCP de entrada foram confirmadas."};}
FirewallDetection FirewallRemediationPolicy::accessFailure(bool d,const QString&t){return{d?FirewallDetectionStatus::AccessDenied:FirewallDetectionStatus::Unknown,t};}
class DiagnosticsRemediationService::WindowsAdapter final:public DiagnosticsRemediationAdapter{public:void detectFirewall(const FirewallRuleSetSpec&s,DetectionCallback cb)override{
#ifdef Q_OS_WIN
 QPointer<QObject>ctx=QCoreApplication::instance();QThreadPool::globalInstance()->start([ctx,s,cb=std::move(cb)]()mutable{auto d=detectCom(s);if(ctx)QMetaObject::invokeMethod(ctx,[cb=std::move(cb),d]()mutable{cb(d);},Qt::QueuedConnection);});
#else
 cb({FirewallDetectionStatus::Unknown,"Disponível somente no Windows."});
#endif
}void launchElevatedFirewallHelper(const FirewallRuleSetSpec&s,LaunchCallback cb)override{
#ifdef Q_OS_WIN
 QString helper=QDir(QCoreApplication::applicationDirPath()).filePath("input-leap-firewall-helper.exe");if(!QFileInfo::exists(helper)){cb(RemediationLaunchResult::Failed);return;}QStringList a{"--add-owned-rules"};for(const auto&r:s.rules){a<<"--rule"<<"--program"<<r.executablePath<<"--ports";for(auto p:r.ports)a<<QString::number(p);}QString params;for(const auto&x:a){if(!params.isEmpty())params+=' ';params+=quote(x);}QPointer<QObject>ctx=QCoreApplication::instance();QThreadPool::globalInstance()->start([ctx,helper,params,cb=std::move(cb)]()mutable{SHELLEXECUTEINFOW e{sizeof(e)};e.fMask=SEE_MASK_NOCLOSEPROCESS;e.lpVerb=L"runas";auto h=helper.toStdWString(),p=params.toStdWString();e.lpFile=h.c_str();e.lpParameters=p.c_str();e.nShow=SW_HIDE;RemediationLaunchResult out;if(!ShellExecuteExW(&e))out=GetLastError()==ERROR_CANCELLED?RemediationLaunchResult::Cancelled:RemediationLaunchResult::Failed;else{WaitForSingleObject(e.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(e.hProcess,&code);CloseHandle(e.hProcess);out=code?RemediationLaunchResult::Failed:RemediationLaunchResult::Started;}if(ctx)QMetaObject::invokeMethod(ctx,[cb=std::move(cb),out]()mutable{cb(out);},Qt::QueuedConnection);});
#else
 Q_UNUSED(s);cb(RemediationLaunchResult::Failed);
#endif
}};
DiagnosticsRemediationService::DiagnosticsRemediationService(DiagnosticsRemediationAdapter*a,QObject*p):QObject(p),adapter_(a){qRegisterMetaType<FirewallDetection>();if(!a){owned_=std::make_unique<WindowsAdapter>();adapter_=owned_.get();}}
DiagnosticsRemediationService::~DiagnosticsRemediationService()=default;
void DiagnosticsRemediationService::inspect(const FirewallRuleSetSpec&s){if(busy_)return;auto v=FirewallRemediationPolicy::validate(s);if(!v.ok){detection_={FirewallDetectionStatus::Unknown,v.reason};emit firewallInspected(detection_);return;}spec_=s;quint64 id=++generation_;QPointer<DiagnosticsRemediationService>self(this);adapter_->detectFirewall(s,[self,id](auto d){if(!self||id!=self->generation_||self->busy_)return;self->detection_=d;emit self->firewallInspected(d);});}
bool DiagnosticsRemediationService::canRemediateFirewall()const{return !busy_&&detection_.status==FirewallDetectionStatus::Missing&&FirewallRemediationPolicy::validate(spec_).ok;}
void DiagnosticsRemediationService::remediateFirewall(bool consent){if(!consent){emit firewallRemediationCancelled();return;}if(!canRemediateFirewall())return;busy_=true;auto launched=spec_;quint64 id=++generation_;QPointer<DiagnosticsRemediationService>self(this);adapter_->launchElevatedFirewallHelper(launched,[self,launched,id](auto r){if(!self||id!=self->generation_)return;if(r==RemediationLaunchResult::Cancelled){self->busy_=false;emit self->firewallRemediationCancelled();return;}if(r!=RemediationLaunchResult::Started){self->busy_=false;emit self->firewallRemediationFailed("A correção elevada não foi concluída.");return;}self->adapter_->detectFirewall(launched,[self,id](auto d){if(!self||id!=self->generation_)return;self->busy_=false;self->detection_=d;emit self->firewallInspected(d);if(d.status==FirewallDetectionStatus::Present)emit self->firewallVerified();else emit self->firewallRemediationFailed("As regras não foram confirmadas após a correção.");});});}
DiagnosticsRemediationActions::DiagnosticsRemediationActions(OpenUrl u,OpenSettings s):openUrl_(std::move(u)),openSettings_(std::move(s)){}bool DiagnosticsRemediationActions::openReceiveFolder(const QString&p)const{QFileInfo f(p);return f.isDir()&&openUrl_&&openUrl_(QUrl::fromLocalFile(f.absoluteFilePath()));}bool DiagnosticsRemediationActions::openSettings()const{if(!openSettings_)return false;openSettings_();return true;}
