#include "ClipboardHistoryDialog.h"
#include "ClipboardHistoryModel.h"

#include <QClipboard>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListView>
#include <QMimeData>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

ClipboardHistoryDialog::ClipboardHistoryDialog(ClipboardHistoryModel* model, QClipboard* clipboard, QWidget* parent) :
    QDialog(parent), model_(model), clipboard_(clipboard)
{
    setWindowTitle(tr("Histórico da área de transferência"));
    setMinimumSize(520, 360);
    setAccessibleName(windowTitle());
    auto* layout = new QVBoxLayout(this);
    auto* intro = new QLabel(tr("Opcional e privado: guarda temporariamente, somente na memória deste aplicativo, textos e imagens que você copiar."), this);
    intro->setWordWrap(true);
    layout->addWidget(intro);
    status_ = new QLabel(this);
    status_->setObjectName(QStringLiteral("historyStatusLabel"));
    status_->setAccessibleName(tr("Estado do histórico"));
    layout->addWidget(status_);
    enable_ = new QPushButton(this);
    enable_->setObjectName(QStringLiteral("enableHistoryButton"));
    layout->addWidget(enable_);
    pause_ = new QPushButton(this);
    pause_->setObjectName(QStringLiteral("pauseClipboardButton"));
    layout->addWidget(pause_);
    empty_ = new QLabel(tr("Nenhum item no histórico."), this);
    empty_->setAlignment(Qt::AlignCenter);
    empty_->setAccessibleName(tr("Histórico vazio"));
    layout->addWidget(empty_);
    list_ = new QListView(this);
    list_->setModel(model_);
    list_->setAccessibleName(tr("Itens copiados recentemente"));
    layout->addWidget(list_, 1);
    auto* actions = new QHBoxLayout;
    copy_ = new QPushButton(tr("Copiar novamente"), this);
    pin_ = new QPushButton(tr("Fixar ou desafixar"), this);
    clear_ = new QPushButton(tr("Limpar tudo"), this);
    actions->addWidget(copy_);
    actions->addWidget(pin_);
    actions->addStretch();
    actions->addWidget(clear_);
    layout->addLayout(actions);
    auto* explanation = new QLabel(sharingExplanation(), this);
    explanation->setWordWrap(true);
    layout->addWidget(explanation);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    layout->addWidget(buttons);

    connect(enable_, &QPushButton::clicked, this, [this] { model_->setEnabled(!model_->isEnabled()); });
    connect(pause_, &QPushButton::clicked, this, [this] { model_->setCapturePaused(!model_->isCapturePaused()); updateState(); });
    connect(copy_, &QPushButton::clicked, this, &ClipboardHistoryDialog::copySelectedAgain);
    connect(pin_, &QPushButton::clicked, this, &ClipboardHistoryDialog::togglePinned);
    connect(clear_, &QPushButton::clicked, this, &ClipboardHistoryDialog::clearAll);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(model_, &ClipboardHistoryModel::enabledChanged, this, &ClipboardHistoryDialog::updateState);
    connect(model_, &QAbstractItemModel::rowsInserted, this, &ClipboardHistoryDialog::updateState);
    connect(model_, &QAbstractItemModel::rowsRemoved, this, &ClipboardHistoryDialog::updateState);
    connect(model_, &QAbstractItemModel::modelReset, this, &ClipboardHistoryDialog::updateState);
    connect(list_->selectionModel(), &QItemSelectionModel::selectionChanged, this, &ClipboardHistoryDialog::updateState);
    updateState();
}

QString ClipboardHistoryDialog::sharingExplanation() const
{
    return tr("Copiar novamente altera a área de transferência deste computador. O compartilhamento com outro computador depende de uma conexão ativa do InputLeap.");
}

void ClipboardHistoryDialog::updateState()
{
    const bool enabled = model_->isEnabled();
    status_->setText(enabled ? tr("Captura %1 nesta sessão — conteúdo somente na memória.").arg(model_->captureStateLabel())
                             : tr("Histórico desativado — nada está sendo guardado."));
    enable_->setText(enabled ? tr("Desativar e apagar") : tr("Ativar histórico nesta sessão"));
    pause_->setText(model_->isCapturePaused() ? tr("Retomar captura") : tr("Pausar captura"));
    pause_->setEnabled(enabled);
    const bool empty = model_->rowCount() == 0;
    empty_->setVisible(empty);
    list_->setVisible(!empty);
    const bool selected = list_->currentIndex().isValid();
    copy_->setEnabled(selected);
    pin_->setEnabled(selected);
    clear_->setEnabled(!empty);
}

void ClipboardHistoryDialog::selectRowForTest(int row)
{
    list_->setCurrentIndex(model_->index(row));
}

void ClipboardHistoryDialog::copySelectedAgain()
{
    const auto* item = model_->entry(list_->currentIndex().row());
    if (!item || !clipboard_) return;
    model_->setCaptureSuppressed(true);
    QTimer::singleShot(0, model_, [model = model_] { model->setCaptureSuppressed(false); });
    if (item->type == ClipboardHistoryModel::Type::Text) {
        clipboard_->setText(item->text, QClipboard::Clipboard);
    } else {
        QImage image;
        if (image.loadFromData(item->imagePng, "PNG")) clipboard_->setImage(image, QClipboard::Clipboard);
    }
}

void ClipboardHistoryDialog::togglePinned()
{
    const QModelIndex selected = list_->currentIndex();
    const auto* item = model_->entry(selected.row());
    if (item) model_->setPinned(selected.row(), !item->pinned);
}

void ClipboardHistoryDialog::clearAll()
{
    model_->clear();
}
