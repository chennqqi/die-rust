QT += core
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = xemulator-oracle

DEP = $$PWD/../../upstream/DIE-engine/dep

INCLUDEPATH += $$DEP/XStaticUnpacker
INCLUDEPATH += $$DEP/XEmulator
INCLUDEPATH += $$DEP/XEmulator/arch

SOURCES += main.cpp

# Enable the upstream emulator branches: adds USE_XEMULATOR, the
# XEmulator x86 core sources and xinstallsimple.cpp via the pinned
# xstaticunpacker.pri (XEmulator is pinned as a sibling checkout at
# dep/XEmulator, exactly the layout upstream expects).
XCONFIG += use_xemulator
include($$DEP/XStaticUnpacker/xstaticunpacker.pri)

SOURCES = $$unique(SOURCES)
HEADERS = $$unique(HEADERS)
