#include "EndpointPolicy.h"
#include <QHostAddress>
#include <QRegularExpression>
#include <algorithm>
QString EndpointPolicy::normalizedHost(const QString& e){QString v=e.trimmed();if(v.startsWith('[')&&v.contains(']'))v=v.mid(1,v.indexOf(']')-1);return v;}
bool EndpointPolicy::isNumeric(const QString&e){return !QHostAddress(normalizedHost(e)).isNull();}
bool EndpointPolicy::isUsableUnicast(const QString&e){const QString h=normalizedHost(e);if(h.isEmpty())return false;const QHostAddress a(h);if(!a.isNull()){const bool unspecified=(a.protocol()==QAbstractSocket::IPv4Protocol&&a.toIPv4Address()==0)||(a.protocol()==QAbstractSocket::IPv6Protocol&&a==QHostAddress(QStringLiteral("::")));return !unspecified&&a!=QHostAddress::Broadcast&&!a.isMulticast()&&!(a.isLinkLocal()&&a.scopeId().isEmpty());}static const QRegularExpression dns(QStringLiteral("^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"));return dns.match(h).hasMatch();}
QString EndpointPolicy::firstUsable(const QStringList& values){struct C{int rank;QString text;};QList<C> c;for(const auto& raw:values){QString t=normalizedHost(raw);if(!isNumeric(t)||!isUsableUnicast(t))continue;QHostAddress a(t);c.append({a.protocol()==QAbstractSocket::IPv4Protocol?0:(a.isLinkLocal()?2:1),t});}std::sort(c.begin(),c.end(),[](const C&a,const C&b){return a.rank==b.rank?a.text<b.text:a.rank<b.rank;});return c.isEmpty()?QString():c.first().text;}
