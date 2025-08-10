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

# SmtpClient-for-Qt
INCLUDEPATH += libs/SmtpClient-for-Qt/src
SOURCES += \
    libs/SmtpClient-for-Qt/src/emailaddress.cpp \
    libs/SmtpClient-for-Qt/src/mimeattachment.cpp \
    libs/SmtpClient-for-Qt/src/mimebase64encoder.cpp \
    libs/SmtpClient-for-Qt/src/mimebase64formatter.cpp \
    libs/SmtpClient-for-Qt/src/mimebytearrayattachment.cpp \
    libs/SmtpClient-for-Qt/src/mimecontentencoder.cpp \
    libs/SmtpClient-for-Qt/src/mimecontentformatter.cpp \
    libs/SmtpClient-for-Qt/src/mimefile.cpp \
    libs/SmtpClient-for-Qt/src/mimehtml.cpp \
    libs/SmtpClient-for-Qt/src/mimeinlinefile.cpp \
    libs/SmtpClient-for-Qt/src/mimemessage.cpp \
    libs/SmtpClient-for-Qt/src/mimemultipart.cpp \
    libs/SmtpClient-for-Qt/src/mimepart.cpp \
    libs/SmtpClient-for-Qt/src/mimeqpencoder.cpp \
    libs/SmtpClient-for-Qt/src/mimeqpformatter.cpp \
    libs/SmtpClient-for-Qt/src/mimetext.cpp \
    libs/SmtpClient-for-Qt/src/quotedprintable.cpp \
    libs/SmtpClient-for-Qt/src/smtpclient.cpp

HEADERS += \
    libs/SmtpClient-for-Qt/src/emailaddress.h \
    libs/SmtpClient-for-Qt/src/mimeattachment.h \
    libs/SmtpClient-for-Qt/src/mimebase64encoder.h \
    libs/SmtpClient-for-Qt/src/mimebase64formatter.h \
    libs/SmtpClient-for-Qt/src/mimebytearrayattachment.h \
    libs/SmtpClient-for-Qt/src/mimecontentencoder.h \
    libs/SmtpClient-for-Qt/src/mimecontentformatter.h \
    libs/SmtpClient-for-Qt/src/mimefile.h \
    libs/SmtpClient-for-Qt/src/mimehtml.h \
    libs/SmtpClient-for-Qt/src/mimeinlinefile.h \
    libs/SmtpClient-for-Qt/src/mimemessage.h \
    libs/SmtpClient-for-Qt/src/mimemultipart.h \
    libs/SmtpClient-for-Qt/src/mimepart.h \
    libs/SmtpClient-for-Qt/src/mimeqpencoder.h \
    libs/SmtpClient-for-Qt/src/mimeqpformatter.h \
    libs/SmtpClient-for-Qt/src/mimetext.h \
    libs/SmtpClient-for-Qt/src/quotedprintable.h \
    libs/SmtpClient-for-Qt/src/smtpclient.h \
    libs/SmtpClient-for-Qt/src/smtpmime_global.h

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
