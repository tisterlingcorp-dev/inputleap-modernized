#pragma once

#include <QString>

#include <QtGlobal>

class WindowsStagedPackageGuard final
{
public:
    WindowsStagedPackageGuard() = default;
    ~WindowsStagedPackageGuard();

    WindowsStagedPackageGuard(const WindowsStagedPackageGuard&) = delete;
    WindowsStagedPackageGuard& operator=(const WindowsStagedPackageGuard&) = delete;

    bool lock(const QString& path);
    bool revalidatePath();
    void release();
    bool isLocked() const;

private:
    void* primaryHandle_ = nullptr;
    void* validationHandle_ = nullptr;
    QString path_;
    quint64 volumeSerial_ = 0;
    quint64 fileIdHigh_ = 0;
    quint64 fileIdLow_ = 0;
};
