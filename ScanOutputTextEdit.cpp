#include "ScanOutputTextEdit.h"

ScanOutputTextEdit::ScanOutputTextEdit(QWidget *parent)
    : QTextEdit(parent)
{
    setAcceptDrops(true);
}

void ScanOutputTextEdit::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
        qDebug() << "ScanOutputTextEdit: Drag Enter Event - Accepted";
    } else {
        event->ignore();
        qDebug() << "ScanOutputTextEdit: Drag Enter Event - Ignored (no URLs)";
    }
}

void ScanOutputTextEdit::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        for (const QUrl &url : event->mimeData()->urls()) {
            QString localPath = url.toLocalFile();
            if (!localPath.isEmpty()) {
                qDebug() << "ScanOutputTextEdit: Dropped file/folder:" << localPath;
                emit fileDropped(localPath);
                event->acceptProposedAction();
                return; // Process only the first dropped item
            }
        }
    }
    event->ignore();
    qDebug() << "ScanOutputTextEdit: Drop Event - Ignored (no valid local file URL)";
}
