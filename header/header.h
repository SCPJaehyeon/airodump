#ifndef HEADER_H
#define HEADER_H
#pragma once
#include <iostream>
#include <cstdio>
#include <stdint.h>
#include <arpa/inet.h>
#include <cstring>
#include <pcap/pcap.h>
#include <map>
#define TYPE    24
#define PWR 18
#define BSSID   40
#define BEACON_LEN  61
#define BEACON_SSID 62
#define PROBE_LEN   49
#define PROBE_SSID  50
#define ReqSTATION 34
#define ResSTATION 28

struct mac {
    u_char MAC[6];
    bool operator<(const mac& omac) const{ //need Modify
        return memcmp(this->MAC, omac.MAC, 6)<0;
    }
};
struct beaconinfo{
    char pwr;
    u_int8_t beacons;
    u_int8_t Chanel;
    std::string essid;
    //u_int8_t Data;
    //u_int8_t enc;
    //u_int8_t auth;

};
struct probeinfo{
    u_char bssidmac[6];
    char pwr;
    u_int8_t frame;
    std::string probe;

};

int cmp_beacon(const u_char *cmp);
int cmp_probereq(const u_char *cmp);
int cmp_proberes(const u_char *cmp);
int show_airodump(char *argv[]);
void Usage(char *argv[]);
#endif
