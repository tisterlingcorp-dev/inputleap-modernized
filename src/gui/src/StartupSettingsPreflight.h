/* InputLeap -- read-only startup gate for persistent settings. */
#pragma once

#include <QtGlobal>

class QSettings;

class StartupSettingsPreflight
{
public:
    enum class Status {
        Valid,
        Missing,
        FormatError,
        AccessError,
        InvalidValue
    };

    static Status inspect(QSettings& settings);
    static qsizetype copyLegacyPublicSettings(const QSettings& source,
                                              QSettings& destination);
};
