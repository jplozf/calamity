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
        return 0;
    }

    a.setWindowIcon(QIcon(":/icons/app_icon.png")); // Set your application icon here
    MainWindow w;
    w.show();
    return a.exec();
}
