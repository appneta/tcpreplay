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

HEADERS += GuiTcpReplay.h  \
    GuiTcpEdit.h \
    TcpEdit.h
FORMS += TcpReplay.ui \
    TcpEdit.ui

LIBS += -L../../lib -lstrl
LIBS += -L../common -lcommon
LIBS += -L../tcpedit -ltcpedit

INCLUDEPATH += ..
INCLUDEPATH += ../..
INCLUDEPATH += ../tcpedit
