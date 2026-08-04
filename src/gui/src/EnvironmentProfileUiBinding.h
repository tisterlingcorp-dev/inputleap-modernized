/* InputLeap -- shared environment profile UI integration. */
#pragma once

#include "EnvironmentProfileController.h"

#include <QObject>
#include <QString>

#include <functional>

class EnvironmentProfileSelector;

class EnvironmentProfileUiBinding final : public QObject
{
    Q_OBJECT
public:
    struct Presentation {
        QString message;
        bool warning = false;
    };
    using ConfirmCapture = std::function<bool(const QString& text)>;
    using ShowResult = std::function<void(const QString& title, const QString& message, bool warning)>;

    EnvironmentProfileUiBinding(EnvironmentProfileSelector& selector,
                                EnvironmentProfileController& controller,
                                ConfirmCapture confirmCapture,
                                ShowResult showResult,
                                QObject* parent = nullptr);

    void refresh(bool available, bool busy, bool externalConfig = false);
    static QString captureConfirmation(EnvironmentProfile::Kind kind);
    static Presentation presentationFor(EnvironmentProfileController::Result result,
                                        EnvironmentProfile::Kind kind, bool capture);

Q_SIGNALS:
    void operationFinished(EnvironmentProfileController::Result result);

private:
    enum class Operation { Activate, Capture };
    void activate(EnvironmentProfile::Kind kind);
    void capture(EnvironmentProfile::Kind kind);
    void finish(EnvironmentProfileController::Result result,
                EnvironmentProfile::Kind kind, Operation operation);
    QString resultMessage(EnvironmentProfileController::Result result,
                          EnvironmentProfile::Kind kind, Operation operation) const;

    EnvironmentProfileSelector& selector_;
    EnvironmentProfileController& controller_;
    ConfirmCapture confirmCapture_;
    ShowResult showResult_;
    bool available_ = true;
    bool busy_ = false;
    bool external_config_ = false;
};
