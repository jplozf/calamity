#include "MainWindow.h"

#include <QApplication>
#include <QSharedMemory>
#include <QMessageBox>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QSharedMemory sharedMemory;
    sharedMemory.setKey("CalamityApp");

    if (sharedMemory.create(1) == false)
    {
        QMessageBox::warning(0, "Calamity is already running", "An instance of Calamity is already running.");
        // To detach the IPC Shared Memory Segment resource of crashed process :
        // lsipc -m
        // ipcrm -m <ID>
        return 0;
    }

    a.setWindowIcon(QIcon(":/icons/app_icon.png")); // Set your application icon here
    MainWindow w;
    // w.show();
    return a.exec();
}

// https://linuxcapable.com/install-clamav-on-fedora-linux/
// sudo systemctl stop clamav-freshclam
// sudo systemctl disable clamav-freshclam
