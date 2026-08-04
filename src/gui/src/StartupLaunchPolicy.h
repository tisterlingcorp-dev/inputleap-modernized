#pragma once

#include <QStringList>

namespace StartupLaunchPolicy {

inline bool suppressAutoStart(const QStringList& arguments)
{
    return arguments.contains(QStringLiteral("--no-auto-start"));
}

} // namespace StartupLaunchPolicy
