#include "SupportReportBuilder.h"
#include <QRegularExpression>

namespace {
QString limited(QString value)
{
    if (value.size() <= SupportReportPolicy::MaxFieldCharacters) return value;
    return value.left(SupportReportPolicy::MaxFieldCharacters - 12) + QStringLiteral(" [TRUNCADO]");
}
void replace(QString &s, const QString &pattern, const QString &replacement,
             QRegularExpression::PatternOptions options = QRegularExpression::CaseInsensitiveOption)
{
    s.replace(QRegularExpression(pattern, options), replacement);
}
QString severity(DiagnosticSeverity value)
{
    switch (value) { case DiagnosticSeverity::Ok: return QStringLiteral("OK");
        case DiagnosticSeverity::Warning: return QStringLiteral("Atenção");
        case DiagnosticSeverity::Error: return QStringLiteral("Erro"); }
    return QStringLiteral("Desconhecido");
}
QString firewallStatus(FirewallDetectionStatus value)
{
    switch (value) { case FirewallDetectionStatus::Present: return QStringLiteral("Presente");
        case FirewallDetectionStatus::Missing: return QStringLiteral("Ausente");
        case FirewallDetectionStatus::AccessDenied: return QStringLiteral("Acesso negado");
        case FirewallDetectionStatus::Unknown: return QStringLiteral("Desconhecido"); }
    return QStringLiteral("Desconhecido");
}
QString mode(SupportReportMode value)
{
    switch (value) { case SupportReportMode::Server: return QStringLiteral("Servidor");
        case SupportReportMode::Client: return QStringLiteral("Cliente");
        case SupportReportMode::Unknown: return QStringLiteral("Desconhecido"); }
    return QStringLiteral("Desconhecido");
}
}

SupportReportBuilder::SupportReportBuilder(Clock clock) : clock_(std::move(clock))
{
    if (!clock_) clock_ = [] { return QDateTime::currentDateTimeUtc(); };
}

QString SupportReportBuilder::sanitize(const QString &input, bool privateMode)
{
    QString s = input;
    s.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));
    s.replace(QLatin1Char('\r'), QLatin1Char('\n'));
    replace(s, QStringLiteral("\\x1b\\[[0-?]*[ -/]*[@-~]"), QString());
    for (int i = s.size() - 1; i >= 0; --i) {
        const ushort u = s.at(i).unicode();
        if ((u < 0x20 && u != '\n' && u != '\t') || u == 0x7f || u == 0x85 ||
            u == 0x061c || u == 0x200e || u == 0x200f || u == 0x2028 || u == 0x2029 ||
            (u >= 0x202a && u <= 0x202e) || (u >= 0x2066 && u <= 0x2069)) s.remove(i, 1);
    }
    // Values occupy one report line. Prevent injected headings or forged rows.
    replace(s, QStringLiteral(R"([\n\t]+)"), QStringLiteral(" "), QRegularExpression::NoPatternOption);
    // Paths can expose local users and network shares and are unnecessary in either mode.
    replace(s, QStringLiteral(R"([A-Za-z]:\\Users\\[^\\/\s]+(?:\\[^\s;,)]+)*)"), QStringLiteral("[CAMINHO REMOVIDO]"));
    replace(s, QStringLiteral(R"(\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\s;,)]+)*)"), QStringLiteral("[CAMINHO REMOVIDO]"));
    replace(s, QStringLiteral(R"(authorization\s*[:=]\s*[^\n;,]+)"), QStringLiteral("[SEGREDO REMOVIDO]"));
    replace(s, QStringLiteral(R"((?:password|passwd|senha|token|cookie|pairing[-_ ]?(?:code|pin)|pin|psk|wif|private[-_ ]?key|api[-_ ]?key)\s*[:=]\s*(?:Bearer\s+)?[^\s;,]+)"), QStringLiteral("[SEGREDO REMOVIDO]"));
    replace(s, QStringLiteral(R"(\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b)"), QStringLiteral("[SEGREDO REMOVIDO]"), QRegularExpression::NoPatternOption);
    replace(s, QStringLiteral(R"(-----BEGIN [^-]*(?:PRIVATE|SECRET)[^-]*-----[\s\S]*?-----END [^-]*-----)"), QStringLiteral("[SEGREDO REMOVIDO]"));
    replace(s, QStringLiteral(R"((?:Server|Data Source|User ID|UID|Password|Pwd)\s*=\s*[^;\n]+)"), QStringLiteral("[SEGREDO REMOVIDO]"));
    if (privateMode) {
        replace(s, QStringLiteral(R"(\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5]?[0-9a-f]{3}-[89ab]?[0-9a-f]{3}-[0-9a-f]{12}\b)"), QStringLiteral("[DISPOSITIVO REMOVIDO]"));
        replace(s, QStringLiteral(R"(\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b)"), QStringLiteral("[DISPOSITIVO REMOVIDO]"));
        replace(s, QStringLiteral(R"((?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]))"), QStringLiteral("[ENDEREÇO REMOVIDO]"));
        // IPv6, including bracketed and scoped forms. A port following ']' remains intact.
        replace(s, QStringLiteral(R"(\[?(?=[0-9a-f:]*:)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[A-Za-z0-9_.-]+)?\]?)"), QStringLiteral("[ENDEREÇO REMOVIDO]"));
        replace(s, QStringLiteral(R"(\b(?:[A-Za-z0-9-]+\.)+(?:local|lan|home|internal|[A-Za-z]{2,63})\b)"), QStringLiteral("[ENDEREÇO REMOVIDO]"));
    }
    return limited(s.trimmed());
}

QString SupportReportBuilder::build(const SupportReportSnapshot &s, const SupportReportPolicy &p) const
{
    auto safe = [&p](const QString &v) { return SupportReportBuilder::sanitize(v, p.privateMode); };
    QStringList out;
    out << QStringLiteral("InputLeap Support Report v1")
        << QStringLiteral("Gerado em (UTC): %1").arg(clock_().toUTC().toString(Qt::ISODate))
        << QStringLiteral("Modo privado: %1").arg(p.privateMode ? QStringLiteral("sim") : QStringLiteral("não"))
        << QString() << QStringLiteral("[Aplicativo e sistema]")
        << QStringLiteral("Versão: %1").arg(safe(s.appVersion))
        << QStringLiteral("SO: %1 %2").arg(safe(s.osProductType), safe(s.osProductVersion))
        << QStringLiteral("Arquitetura: %1").arg(safe(s.cpuArchitecture))
        << QStringLiteral("Modo: %1").arg(mode(s.mode));
    out << QString() << QStringLiteral("[Estados]")
        << QStringLiteral("Núcleo: %1").arg(safe(s.coreState.isEmpty() ? QStringLiteral("Não informado") : s.coreState))
        << QStringLiteral("Par: %1").arg(safe(s.peerState.isEmpty() ? QStringLiteral("Não informado") : s.peerState));
    if (!s.endpoint.isEmpty()) {
        QString endpoint = safe(s.endpoint);
        if (p.privateMode) {
            const auto portMatch = QRegularExpression(QStringLiteral(R"((?::|\]:)(\d{1,5})$)")).match(s.endpoint.trimmed());
            endpoint = QStringLiteral("[ENDEREÇO REMOVIDO]");
            if (portMatch.hasMatch()) endpoint += QStringLiteral(":%1").arg(portMatch.captured(1));
        }
        out << QStringLiteral("Endereço: %1").arg(endpoint);
    }
    if (!s.deviceDisplayName.isEmpty()) out << QStringLiteral("Dispositivo: %1").arg(p.privateMode ? QStringLiteral("[DISPOSITIVO REMOVIDO]") : safe(s.deviceDisplayName));
    if (!s.peerUuid.isNull()) out << QStringLiteral("UUID do par: %1").arg(p.privateMode ? QStringLiteral("[DISPOSITIVO REMOVIDO]") : s.peerUuid.toString(QUuid::WithoutBraces));
    out << QString() << QStringLiteral("[Diagnóstico]");
    for (const auto &c : s.diagnostics.checks)
        out << QStringLiteral("%1 | %2 | %3%4").arg(safe(c.id), severity(c.severity), safe(c.simple),
            c.technical.isEmpty() ? QString() : QStringLiteral(" | %1").arg(safe(c.technical)));
    out << QString() << QStringLiteral("[Firewall]")
        << QStringLiteral("Estado: %1").arg(firewallStatus(s.firewall.status));
    if (!s.firewall.technical.isEmpty()) out << QStringLiteral("Detalhe: %1").arg(safe(s.firewall.technical));
    out << QString() << QStringLiteral("[Erros recentes sanitizados]");
    const int count = (std::min)(static_cast<int>(s.recentErrors.size()), SupportReportPolicy::MaxErrorCount);
    for (int i = 0; i < count; ++i) out << QStringLiteral("- %1").arg(safe(s.recentErrors.at(i)));
    if (s.recentErrors.size() > count) out << QStringLiteral("- [TRUNCADO]");
    if (count == 0) out << QStringLiteral("Nenhum erro seguro fornecido.");
    QString result = out.join(QLatin1Char('\n')) + QLatin1Char('\n');
    QByteArray utf8 = result.toUtf8();
    if (utf8.size() > SupportReportPolicy::MaxUtf8Bytes) {
        const QByteArray marker("\n[TRUNCADO]\n");
        utf8.truncate(SupportReportPolicy::MaxUtf8Bytes - marker.size());
        while (!utf8.isEmpty() && QString::fromUtf8(utf8).endsWith(QChar::ReplacementCharacter)) utf8.chop(1);
        result = QString::fromUtf8(utf8) + QString::fromLatin1(marker);
        while (result.toUtf8().size() > SupportReportPolicy::MaxUtf8Bytes) result.chop(1);
    }
    return result;
}
