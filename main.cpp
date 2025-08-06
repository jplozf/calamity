#include "MainWindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setWindowIcon(QIcon(":/icons/app_icon.png")); // Set your application icon here
    MainWindow w;
    w.show();
    return a.exec();
}
