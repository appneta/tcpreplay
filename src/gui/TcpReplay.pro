# -------------------------------------------------
# Project created by QtCreator 2009-02-18T14:55:48
# -------------------------------------------------
QT += network
TARGET = tcpreplay-gui
TEMPLATE = app
SOURCES += GuiTcpReplay.cpp  \
    GuiTcpEdit.cpp \
    main.cpp \
    TcpEdit.cpp

HEADERS += TcpReplay.h \
    GuiTcpReplay.h  \
    GuiTcpEdit.h \
    TcpEdit.h
FORMS += TcpReplay.ui \
    TcpEdit.ui

LIBS += -L../tcpedit -ltcpedit
LIBS += -L../../lib -lstrl
LIBS += -L../common -lcommon

INCLUDEPATH += ..
INCLUDEPATH += ../..
INCLUDEPATH += ../tcpedit
