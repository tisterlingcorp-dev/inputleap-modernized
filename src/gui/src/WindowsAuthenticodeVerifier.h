#pragma once

#include <QByteArray>
#include <QString>

namespace WindowsAuthenticode {

struct Verification
{
    bool trusted = false;
    QByteArray signerSha256;
    qint64 nativeTrustStatus = 0;
};

Verification inspect(const QString& path);
bool verifyPinnedPublisher(const QString& path,
                           const QByteArray& expectedSignerSha256);

}
