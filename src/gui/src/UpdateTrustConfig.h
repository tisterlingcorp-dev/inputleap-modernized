#pragma once

#include "UpdateService.h"

#include <QUrl>

struct UpdateTrustConfig
{
    QUrl manifestUrl;
    UpdateService::TrustedKeys trustedKeys;
    int minimumValidSignatures = 1;

    static UpdateTrustConfig production();
};
