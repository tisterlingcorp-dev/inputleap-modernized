#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <netfw.h>
#include <oleauto.h>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
namespace{
constexpr wchar_t GROUP[]=L"InputLeap";
struct Spec{std::filesystem::path program;std::vector<unsigned short>ports;};
bool unsafe(const std::wstring&s){return s.find(L'\r')!=s.npos||s.find(L'\n')!=s.npos||s.find(L'\0')!=s.npos;}
bool number(const std::wstring&s,unsigned short&out){if(s.empty()||!std::all_of(s.begin(),s.end(),iswdigit))return false;wchar_t*end=nullptr;auto n=wcstoul(s.c_str(),&end,10);if(*end||n<1||n>65535)return false;out=(unsigned short)n;return true;}
bool parse(int ac,wchar_t**av,std::vector<Spec>&specs){if(ac<7||std::wstring(av[1])!=L"--add-owned-rules")return false;int i=2;while(i<ac){if(specs.size()==2||std::wstring(av[i++])!=L"--rule"||i>=ac||std::wstring(av[i++])!=L"--program"||i>=ac)return false;Spec s;s.program=av[i++];if(unsafe(s.program.native())||!s.program.is_absolute())return false;if(i>=ac||std::wstring(av[i++])!=L"--ports")return false;while(i<ac&&std::wstring(av[i])!=L"--rule"){unsigned short p;if(!number(av[i++],p)||std::find(s.ports.begin(),s.ports.end(),p)!=s.ports.end())return false;s.ports.push_back(p);}if(s.ports.empty())return false;specs.push_back(std::move(s));}return !specs.empty();}
std::wstring portText(std::vector<unsigned short>p){std::sort(p.begin(),p.end());std::wstring s;for(auto n:p){if(!s.empty())s+=L",";s+=std::to_wstring(n);}return s;}
uint64_t fnv(const std::wstring&s){uint64_t h=14695981039346656037ull;for(wchar_t c:s){wchar_t x=(wchar_t)towlower(c);for(unsigned j=0;j<sizeof(wchar_t);++j){h^=(x>>(j*8))&255;h*=1099511628211ull;}}return h;}
std::wstring nameFor(const Spec&s){auto key=s.program.native()+L"|"+portText(s.ports);wchar_t hex[17];swprintf_s(hex,L"%016llx",(unsigned long long)fnv(key));return std::wstring(L"InputLeap Firewall ")+hex;}
HRESULT putBstr(INetFwRule*r,HRESULT(INetFwRule::*put)(BSTR),const std::wstring&v){BSTR b=SysAllocString(v.c_str());if(!b)return E_OUTOFMEMORY;HRESULT hr=(r->*put)(b);SysFreeString(b);return hr;}
bool sameGroup(INetFwRule*r){BSTR b=nullptr;HRESULT hr=r->get_Grouping(&b);bool ok=SUCCEEDED(hr)&&b&&!_wcsicmp(b,GROUP);SysFreeString(b);return ok;}
HRESULT install(INetFwRules*rules,const Spec&s){std::wstring name=nameFor(s);BSTR bn=SysAllocString(name.c_str());if(!bn)return E_OUTOFMEMORY;INetFwRule*old=nullptr;HRESULT item=rules->Item(bn,&old);if(SUCCEEDED(item)&&!sameGroup(old)){old->Release();SysFreeString(bn);return E_ACCESSDENIED;}if(FAILED(item)&&item!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)){SysFreeString(bn);return item;}
 INetFwRule*fresh=nullptr;HRESULT hr=CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwRule),(void**)&fresh);if(SUCCEEDED(hr))hr=putBstr(fresh,&INetFwRule::put_Name,name);if(SUCCEEDED(hr))hr=putBstr(fresh,&INetFwRule::put_Grouping,GROUP);if(SUCCEEDED(hr))hr=putBstr(fresh,&INetFwRule::put_Description,L"InputLeap TCP inbound rule (managed by InputLeap)");if(SUCCEEDED(hr))hr=putBstr(fresh,&INetFwRule::put_ApplicationName,s.program.native());if(SUCCEEDED(hr))hr=fresh->put_Protocol(NET_FW_IP_PROTOCOL_TCP);if(SUCCEEDED(hr))hr=putBstr(fresh,&INetFwRule::put_LocalPorts,portText(s.ports));if(SUCCEEDED(hr))hr=fresh->put_Direction(NET_FW_RULE_DIR_IN);if(SUCCEEDED(hr))hr=fresh->put_Profiles(NET_FW_PROFILE2_DOMAIN|NET_FW_PROFILE2_PRIVATE);if(SUCCEEDED(hr))hr=fresh->put_Action(NET_FW_ACTION_ALLOW);if(SUCCEEDED(hr))hr=fresh->put_Enabled(VARIANT_TRUE);
 if(SUCCEEDED(hr)&&old){old->Release();old=nullptr;hr=rules->Remove(bn);}if(SUCCEEDED(hr))hr=rules->Add(fresh);if(old)old->Release();if(fresh)fresh->Release();SysFreeString(bn);return hr;}
}
int wmain(int ac,wchar_t**av){std::vector<Spec>s;if(!parse(ac,av,s))return 2;std::error_code ec;auto helper=std::filesystem::canonical(av[0],ec);if(ec)return 2;std::vector<std::wstring>names;for(auto&x:s){x.program=std::filesystem::canonical(x.program,ec);if(ec||_wcsicmp(x.program.parent_path().c_str(),helper.parent_path().c_str()))return 2;auto fn=x.program.filename().native();if(_wcsicmp(fn.c_str(),L"input-leaps.exe")&&_wcsicmp(fn.c_str(),L"input-leap.exe"))return 2;for(auto&n:names)if(!_wcsicmp(n.c_str(),fn.c_str()))return 2;names.push_back(fn);if(x.ports.size()!=1)return 2;}HRESULT ci=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(ci))return 3;INetFwPolicy2*p=nullptr;HRESULT hr=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),(void**)&p);INetFwRules*r=nullptr;if(SUCCEEDED(hr))hr=p->get_Rules(&r);if(p)p->Release();for(const auto&x:s)if(SUCCEEDED(hr))hr=install(r,x);if(r)r->Release();CoUninitialize();return SUCCEEDED(hr)?0:6;}
#else
int main(){return 1;}
#endif
