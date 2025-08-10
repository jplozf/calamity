QT       += core gui network

QT += widgets

CONFIG += c++17

VERSION = 0
GIT_HASH = $$system(git rev-parse --short HEAD)
GIT_COMMIT_COUNT = $$system(git rev-list --count HEAD)

DEFINES += "APP_VERSION=\"\\\"$$VERSION\\\"\""
DEFINES += "GIT_HASH=\\\"\"$$GIT_HASH\\\"\""
DEFINES += "GIT_COMMIT_COUNT=\\\"\"$$GIT_COMMIT_COUNT\\\"\""

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    MainWindow.cpp \
    ScanOutputTextEdit.cpp

HEADERS += \
    MainWindow.h \
    ScanOutputTextEdit.h

FORMS += \
    MainWindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
   calamity.qrc
