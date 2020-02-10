TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        cpp/airodump.cpp \
        cpp/main.cpp \
        cpp/pkt_cmp.cpp \
        cpp/show.cpp

HEADERS += \
    header/header.h
