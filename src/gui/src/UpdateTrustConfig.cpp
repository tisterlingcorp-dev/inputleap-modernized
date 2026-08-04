#include "UpdateTrustConfig.h"

UpdateTrustConfig UpdateTrustConfig::production()
{
    UpdateTrustConfig config;
    config.manifestUrl = QUrl(QStringLiteral(
        "https://raw.githubusercontent.com/tisterlingcorp-dev/"
        "inputleap-modernized/master/updates/stable/manifest.json"));
    const auto policy = [](const char* publicHex, const char* notBefore,
                           const char* notAfter, bool revoked = false) {
        UpdateService::TrustedKey key{QByteArray::fromHex(QByteArray(publicHex))};
        key.notBeforeUtc = QDateTime::fromString(QString::fromLatin1(notBefore), Qt::ISODate);
        key.notAfterUtc = QDateTime::fromString(QString::fromLatin1(notAfter), Qt::ISODate);
        key.revoked = revoked;
        return key;
    };
    config.trustedKeys.insert(
        QStringLiteral("inputleap-modernized-release-2026-01"),
        policy("3bdcc40b918377b0e4468acac69df830b8f9f8e9f7701604202082d61cb7aca6",
               "2026-01-01T00:00:00Z", "2028-01-01T00:00:00Z"));
    config.trustedKeys.insert(
        QStringLiteral("inputleap-modernized-release-2026-02"),
        policy("a0796391ac0378562fa81f24b35ed4bafbcd2b32e28b1018b6295ebc6776036e",
               "2026-07-01T00:00:00Z", "2028-07-01T00:00:00Z"));
    config.trustedKeys.insert(
        QStringLiteral("inputleap-modernized-release-2026-03"),
        policy("f5a9f310b136d579b57d7a4c5540952f7012af94491e5925aa31126c423c2bd0",
               "2026-07-01T00:00:00Z", "2029-01-01T00:00:00Z"));
    config.minimumValidSignatures = 2;
    return config;
}
