QT += core
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = demangle-oracle

DEP = $$PWD/../../upstream/DIE-engine/dep

INCLUDEPATH += $$DEP/XDemangle

SOURCES += main.cpp
SOURCES += $$DEP/XDemangle/xdemangle.cpp
HEADERS += $$DEP/XDemangle/xdemangle.h
