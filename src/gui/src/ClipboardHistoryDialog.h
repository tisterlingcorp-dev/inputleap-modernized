#pragma once

#include <QDialog>

class ClipboardHistoryModel;
class QClipboard;
class QLabel;
class QListView;
class QPushButton;

class ClipboardHistoryDialog final : public QDialog
{
    Q_OBJECT
public:
    ClipboardHistoryDialog(ClipboardHistoryModel* model, QClipboard* clipboard, QWidget* parent = nullptr);
    QString sharingExplanation() const;
    void selectRowForTest(int row);

public Q_SLOTS:
    void copySelectedAgain();
    void clearAll();

private:
    void updateState();
    void togglePinned();

    ClipboardHistoryModel* model_;
    QClipboard* clipboard_;
    QLabel* status_;
    QLabel* empty_;
    QListView* list_;
    QPushButton* enable_ = nullptr;
    QPushButton* pause_ = nullptr;
    QPushButton* copy_;
    QPushButton* pin_;
    QPushButton* clear_;
};
