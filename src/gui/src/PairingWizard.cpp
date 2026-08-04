#include "PairingWizard.h"

#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QTimer>
#include <QVBoxLayout>

PairingWizard::PairingWizard(const QUuid&i,const QUuid&l,const QHostAddress&a,quint16 p,QWidget*parent)
    :QWizard(parent),inviter_(i),local_(l),peer_(i),address_(a),port_(p){buildUi();wireController();}

PairingWizard::PairingWizard(const QUuid&l,const QUuid&r,const QHostAddress&a,QWidget*parent)
    :QWizard(parent),local_(l),peer_(r),address_(a),inviterRole_(true){
    const auto made=controller_.listen(local_,peer_,address_,0);
    if(made){displayCode_=QString::fromLatin1(made->displayCode);port_=controller_.port();}
    buildUi();wireController();
    if(made) QTimer::singleShot(0,this,[this]{emit listenerReady(port_);});
}

void PairingWizard::buildUi(){
    setWindowTitle(tr("Adicionar computador"));setOption(QWizard::NoBackButtonOnStartPage);setWizardStyle(QWizard::ModernStyle);
    auto* endpoint=new QWizardPage;endpoint->setTitle(inviterRole_?tr("Mostrar código neste computador"):tr("Escolher computador"));auto* ev=new QVBoxLayout(endpoint);
    if(inviterRole_){
        auto* explanation=new QLabel(tr("No outro computador, escolha “Digitar código mostrado no outro” e informe este código:"),endpoint);explanation->setWordWrap(true);ev->addWidget(explanation);
        auto* shown=new QLabel(displayCode_.isEmpty()?tr("Não foi possível abrir o convite."):displayCode_,endpoint);shown->setObjectName("pairingDisplayCode");shown->setTextInteractionFlags(Qt::NoTextInteraction);shown->setStyleSheet("font-size:28px;font-weight:700;letter-spacing:6px");ev->addWidget(shown,0,Qt::AlignCenter);
        ev->addWidget(new QLabel(tr("Porta: %1 • UUID: %2").arg(port_).arg(local_.toString(QUuid::WithoutBraces)),endpoint));
    }else{
        ev->addWidget(new QLabel(tr("Computador: %1:%2").arg(address_.toString()).arg(port_),endpoint));
        ev->addWidget(new QLabel(tr("A conexão usa um canal público protegido pelo código mostrado no outro computador."),endpoint));
    }
    setPage(EndpointPage,endpoint);
    if(!inviterRole_){auto* cp=new QWizardPage;cp->setTitle(tr("Confirmar código"));auto* form=new QFormLayout(cp);code_=new QLineEdit(cp);code_->setObjectName("pairingCode");code_->setMaxLength(6);code_->setInputMethodHints(Qt::ImhDigitsOnly|Qt::ImhSensitiveData|Qt::ImhNoPredictiveText);code_->setEchoMode(QLineEdit::Password);form->addRow(tr("Código de 6 dígitos:"),code_);error_=new QLabel(cp);error_->setObjectName("pairingError");error_->setStyleSheet("color:#b42318");error_->setWordWrap(true);form->addRow(error_);setPage(CodePage,cp);}
    else {error_=new QLabel(this);error_->setObjectName("pairingError");page(EndpointPage)->layout()->addWidget(error_);}
    auto* profile=new QWizardPage;profile->setTitle(tr("Nome do computador"));auto* pf=new QFormLayout(profile);alias_=new QLineEdit(profile);alias_->setMaxLength(80);auto* permissions=new QLabel(tr("Permissões detalhadas serão configuradas depois"),profile);permissions->setWordWrap(true);pf->addRow(tr("Apelido neste computador:"),alias_);pf->addRow(permissions);setPage(ProfilePage,profile);
}
void PairingWizard::wireController(){
    connect(&controller_,&PairingController::authenticatedDeviceMetadata,this,&PairingWizard::authenticatedDeviceMetadata);
    connect(&controller_,&PairingController::pairingPortChanged,this,&PairingWizard::listenerReady);
    connect(&controller_,&PairingController::inviteReceived,this,[this]{error_->setText(tr("Convite recebido. Digite o código mostrado no outro computador."));});
    connect(&controller_,&PairingController::failed,this,[this](const QString&e){error_->setText(e);if(button(QWizard::NextButton))button(QWizard::NextButton)->setEnabled(true);});
    connect(&controller_,&PairingController::paired,this,[this](const QUuid& peer){auto key=controller_.pairKey(peer);if(!key){error_->setText(tr("A chave da sessão não pôde ser preservada."));return;}confirmed_=true;error_->clear();if(currentId()!=ProfilePage)next();});
    connect(this,&QWizard::finished,this,[this](int result){if(result==QDialog::Accepted&&confirmed_){auto key=controller_.pairKey(peer_);if(key)emit pairingCompleted(peer_,*key,alias());}});
}
bool PairingWizard::validateCurrentPage(){
    if(currentId()==EndpointPage){if(inviterRole_)return confirmed_;if(!started_){started_=true;controller_.connectTo(inviter_,local_,address_,port_);}return true;}
    if(currentId()==CodePage){if(confirmed_)return true;const QString c=code_->text();if(!QRegularExpression("^[0-9]{6}$").match(c).hasMatch()){error_->setText(tr("Digite exatamente os 6 números do código."));return false;}error_->setText(tr("Confirmando com segurança…"));button(QWizard::NextButton)->setEnabled(false);controller_.submitCode(c.toLatin1());code_->clear();return false;}return true;
}
void PairingWizard::reject(){controller_.cancel();emit cancelledSafely();QWizard::reject();}
QString PairingWizard::errorText()const{return error_?error_->text():QString();}void PairingWizard::setCodeForTest(const QString&s){if(code_)code_->setText(s);}QString PairingWizard::alias()const{return alias_->text().trimmed();}
