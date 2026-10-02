QT += core
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = nfd-oracle

DEP = $$PWD/../../upstream/DIE-engine/dep

INCLUDEPATH += $$DEP/SpecAbstract
INCLUDEPATH += $$DEP/SpecAbstract/modules
INCLUDEPATH += $$DEP/XScanEngine
INCLUDEPATH += $$DEP/Formats

SOURCES += main.cpp

# XEmulator is an optional unpacker emulation layer not pinned in the
# DIE-engine submodule set at our base commit; skip it.
XCONFIG += no_xemulator

include($$DEP/SpecAbstract/specabstract.pri)

# xarchive.pri and xzip.pri both list diskimages/xvmdkarchive — dedupe so
# the object is linked once.
SOURCES = $$unique(SOURCES)
HEADERS = $$unique(HEADERS)
