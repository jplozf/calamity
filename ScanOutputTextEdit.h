#ifndef SCANOUTPUTTEXTEDIT_H
#define SCANOUTPUTTEXTEDIT_H

#include <QTextEdit>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QDebug>

class ScanOutputTextEdit : public QTextEdit
{
    Q_OBJECT

public:
    explicit ScanOutputTextEdit(QWidget *parent = nullptr);

signals:
    void fileDropped(const QString &path);

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;
};

#endif // SCANOUTPUTTEXTEDIT_H
