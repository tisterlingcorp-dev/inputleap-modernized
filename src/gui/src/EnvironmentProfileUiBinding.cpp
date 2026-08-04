/* InputLeap -- shared environment profile UI integration. */
#include "EnvironmentProfileUiBinding.h"

#include "EnvironmentProfileSelector.h"

EnvironmentProfileUiBinding::EnvironmentProfileUiBinding(
    EnvironmentProfileSelector& selector,
    EnvironmentProfileController& controller,
    ConfirmCapture confirmCapture,
    ShowResult showResult,
    QObject* parent) :
    QObject(parent),
    selector_(selector),
    controller_(controller),
    confirmCapture_(std::move(confirmCapture)),
    showResult_(std::move(showResult))
{
    selector_.setSwitchEnabled(false,
        tr("Os perfis de ambiente estão indisponíveis até a configuração ser verificada."));
    connect(&selector_, &EnvironmentProfileSelector::applyRequested,
            this, &EnvironmentProfileUiBinding::activate);
    connect(&selector_, &EnvironmentProfileSelector::captureRequested,
            this, &EnvironmentProfileUiBinding::capture);
    connect(&controller_, &EnvironmentProfileController::activeProfileChanged,
            &selector_, &EnvironmentProfileSelector::setActiveKind);
    selector_.setActiveKind(controller_.activeKind());
}

void EnvironmentProfileUiBinding::refresh(bool available, bool busy, bool externalConfig)
{
    available_ = available;
    busy_ = busy;
    external_config_ = externalConfig;
    if (external_config_) {
        selector_.setSwitchEnabled(false,
            tr("A configuração externa está ativa; perfis de ambiente não podem alterar esse layout nesta versão."));
        return;
    }
    if (!available_) {
        selector_.setSwitchEnabled(false,
            tr("Os perfis de ambiente não estão disponíveis porque a configuração não pôde ser carregada."));
        return;
    }
    if (busy_) {
        selector_.setSwitchEnabled(false,
            tr("Pare o InputLeap e aguarde o fim das transferências para alterar perfis."));
        return;
    }
    selector_.setActiveKind(controller_.activeKind());
    selector_.setSwitchEnabled(true);
}

QString EnvironmentProfileUiBinding::captureConfirmation(EnvironmentProfile::Kind kind)
{
    return tr("Salvar layout, dispositivos e recursos permitidos atualmente em %1? Segredos e dados de rede não serão incluídos.")
        .arg(EnvironmentProfile::canonicalDisplayName(kind));
}

void EnvironmentProfileUiBinding::activate(EnvironmentProfile::Kind kind)
{
    if (!available_ || busy_ || external_config_) return;
    finish(controller_.activate(kind, EnvironmentProfileController::ActivationSource::Manual),
           kind, Operation::Activate);
}

void EnvironmentProfileUiBinding::capture(EnvironmentProfile::Kind kind)
{
    if (!available_ || busy_ || external_config_) return;
    if (!confirmCapture_ || !confirmCapture_(captureConfirmation(kind))) return;
    finish(controller_.capture(kind), kind, Operation::Capture);
}

void EnvironmentProfileUiBinding::finish(EnvironmentProfileController::Result result,
                                          EnvironmentProfile::Kind kind,
                                          Operation operation)
{
    selector_.setActiveKind(controller_.activeKind());
    refresh(available_, busy_, external_config_);
    if (showResult_) {
        const auto presentation = presentationFor(result, kind, operation == Operation::Capture);
        showResult_(tr("Perfis de ambiente"), presentation.message, presentation.warning);
    }
    Q_EMIT operationFinished(result);
}

EnvironmentProfileUiBinding::Presentation EnvironmentProfileUiBinding::presentationFor(
    EnvironmentProfileController::Result result, EnvironmentProfile::Kind kind, bool capture)
{
    const QString name = EnvironmentProfile::canonicalDisplayName(kind);
    Presentation presentation;
    presentation.warning = result != EnvironmentProfileController::Result::Success &&
                           result != EnvironmentProfileController::Result::Unchanged;
    switch (result) {
    case EnvironmentProfileController::Result::Success:
        presentation.message = capture
            ? tr("Estado atual salvo no perfil %1.").arg(name)
            : tr("Perfil %1 aplicado com sucesso.").arg(name);
        break;
    case EnvironmentProfileController::Result::Unchanged:
        presentation.message = tr("O perfil %1 já está ativo; nenhuma alteração foi feita.").arg(name);
        break;
    case EnvironmentProfileController::Result::Busy:
        presentation.message = tr("Pare o InputLeap e aguarde o fim das transferências antes de alterar perfis.");
        break;
    case EnvironmentProfileController::Result::ExternalConfigUnsupported:
        presentation.message = tr("Perfis de ambiente não podem alterar um layout de configuração externa nesta versão.");
        break;
    case EnvironmentProfileController::Result::PersistenceError:
        presentation.message = tr("Não foi possível salvar o perfil com segurança. A configuração anterior foi preservada.");
        break;
    case EnvironmentProfileController::Result::InvalidProfile:
        presentation.message = tr("O perfil selecionado é inválido ou não está disponível.");
        break;
    case EnvironmentProfileController::Result::AutomationRequiresConsent:
        presentation.message = tr("A troca automática de perfil exige consentimento explícito.");
        break;
    case EnvironmentProfileController::Result::ConcurrentModification:
        presentation.message = tr("A configuração foi alterada por outro processo. Revise o estado atual e tente novamente manualmente.");
        break;
    case EnvironmentProfileController::Result::IndeterminateState:
        presentation.message = tr("O estado da configuração ficou incerto. As permissões foram bloqueadas por segurança; reabra o InputLeap antes de tentar novamente.");
        break;
    case EnvironmentProfileController::Result::Reentrant:
        presentation.message = tr("Já existe uma operação de perfil em andamento. Aguarde sua conclusão antes de tentar novamente.");
        break;
    case EnvironmentProfileController::Result::WrongThread:
        presentation.message = tr("A operação foi bloqueada por um erro de segurança interna. Reabra o InputLeap antes de tentar novamente.");
        break;
    }
    return presentation;
}

QString EnvironmentProfileUiBinding::resultMessage(EnvironmentProfileController::Result result,
                                                    EnvironmentProfile::Kind kind,
                                                    Operation operation) const
{
    return presentationFor(result, kind, operation == Operation::Capture).message;
}
