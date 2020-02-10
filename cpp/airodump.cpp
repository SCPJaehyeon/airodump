#include "header/header.h"
using namespace std;

int show_airodump(char* argv[]){
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // if file : pcap_open_offline
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    u_char char_beacon_bssid[6], char_probe_station[6], char_probe_bssid[6]; //beacon, probe init
    u_int i=1, j=1 ,essid_length=0, probe_length=0;

    u_int cnt_beacon = 0, pwr_beacon=0, chanel_beacon=0; //beacon
    string essid_beacon = "";

    u_int cnt_frame = 0, cnt_frame2 = 0, pwr_probe = 0, pwr_probe2 = 0; //probe
    string essid_probe = "", essid_probe2 = "";

    //Struct
    struct mac bssid_s, station_s;
    struct beaconinfo beaconinfo_s;
    struct probeinfo probeinfo_s;

    //Map<struct, struct>
    map<mac, beaconinfo> beacon_info;
    map<mac, beaconinfo>::iterator beacon_infoit;
    map<mac, probeinfo> probe_info;
    map<mac, probeinfo>::iterator probe_infoit;

    while(res != -1 || res != -2){
        if(cmp_beacon(&packet[TYPE])==1 || cmp_probereq(&packet[TYPE])==1 || cmp_proberes(&packet[TYPE])==1){
            system("clear");
            i = 1, j = 1;
            if(cmp_beacon(&packet[TYPE])==1){ //BEACON FRAME
                memcpy(&bssid_s.MAC, &packet[BSSID],6); //ap bssid
                memcpy(&beaconinfo_s.pwr, &packet[PWR], 1); //ap pwr
                memcpy(&essid_length, &packet[BEACON_LEN],1);
                beaconinfo_s.essid.resize(essid_length);
                memcpy((char*)beaconinfo_s.essid.data(), &packet[BEACON_SSID],essid_length); //ap essid
                memcpy(&beaconinfo_s.Chanel, &packet[BEACON_LEN+essid_length+13],1); //ap channel
                auto ret = beacon_info.insert(make_pair(bssid_s,beaconinfo_s));
                if(ret.second == true) { //if new key
                    memcpy(&beaconinfo_s.pwr, &packet[PWR], 1);
                    memcpy(&essid_length, &packet[BEACON_LEN],1);
                    beaconinfo_s.essid.resize(essid_length);
                    memcpy((char*)beaconinfo_s.essid.data(), &packet[BEACON_SSID],essid_length);
                    memcpy(&beaconinfo_s.Chanel, &packet[BEACON_LEN+essid_length+13],1);
                    cnt_beacon = 1;
                    beaconinfo_s.beacons = cnt_beacon;
                    beacon_info[bssid_s] = beaconinfo_s;
                }else if(ret.second == false){ //if exist
                    pwr_beacon = beacon_info.find(bssid_s)->second.pwr;
                    essid_beacon = beacon_info.find(bssid_s)->second.essid.c_str();
                    chanel_beacon = beacon_info.find(bssid_s)->second.Chanel;
                    cnt_beacon = beacon_info.find(bssid_s)->second.beacons + 1; //beacons count +1
                    beaconinfo_s.beacons = pwr_beacon;
                    beaconinfo_s.essid = essid_beacon;
                    beaconinfo_s.Chanel = chanel_beacon;
                    beaconinfo_s.beacons = cnt_beacon;
                    beacon_info[bssid_s] = beaconinfo_s;
                }
            }
            else if(cmp_probereq(&packet[TYPE])==1){ //PROBE REQUEST
                memcpy(&station_s.MAC, &packet[ReqSTATION],6); //station
                memcpy(&probeinfo_s.bssidmac, &packet[BSSID],6);
                memcpy(&probeinfo_s.pwr, &packet[PWR],1);
                memcpy(&probe_length, &packet[PROBE_LEN],1);
                probeinfo_s.probe.resize(probe_length);
                memcpy((char*)probeinfo_s.probe.data(), &packet[PROBE_SSID],probe_length);
                auto ret2 = probe_info.insert(make_pair(station_s,probeinfo_s));
                if(ret2.second == true) { //if new key
                    memcpy(&probeinfo_s.bssidmac, &packet[BSSID],6);
                    memcpy(&probeinfo_s.pwr, &packet[PWR],1);
                    memcpy(&probe_length, &packet[PROBE_LEN],1);
                    probeinfo_s.probe.resize(probe_length);
                    memcpy((char*)probeinfo_s.probe.data(), &packet[PROBE_SSID],probe_length);
                    cnt_frame = 1;
                    probeinfo_s.frame = cnt_frame;
                    probe_info[station_s] = probeinfo_s;
                }else if(ret2.second == false){ //if exist
                    pwr_probe = probe_info.find(station_s)->second.pwr;
                    essid_probe = probe_info.find(station_s)->second.probe;
                    cnt_frame = probe_info.find(station_s)->second.frame + 1; //frame count +1
                    probeinfo_s.pwr = pwr_probe;
                    probeinfo_s.probe = essid_probe;
                    probeinfo_s.frame = cnt_frame;
                    probe_info[station_s] = probeinfo_s;
                }
            }
            else if(cmp_proberes(&packet[TYPE])==1){ //PROBE RESPONSE
                memcpy(&station_s.MAC, &packet[ResSTATION],6);
                memcpy(&probeinfo_s.bssidmac, &packet[BSSID],6);
                memcpy(&probeinfo_s.pwr, &packet[PWR],1);
                memcpy(&probe_length, &packet[0],1); //none
                probeinfo_s.probe.resize(probe_length);
                memcpy((char*)probeinfo_s.probe.data(), &packet[62],probe_length);
                auto ret3 = probe_info.insert(make_pair(station_s,probeinfo_s));
                if(ret3.second == true) { //if new key
                    memcpy(&probeinfo_s.bssidmac, &packet[PROBE_SSID],6);
                    memcpy(&probeinfo_s.pwr, &packet[PWR],1);
                    memcpy(&probe_length, &packet[0],1); //none
                    probeinfo_s.probe.resize(probe_length);
                    memcpy((char*)probeinfo_s.probe.data(), &packet[PROBE_SSID],probe_length);
                    cnt_frame2 = 1;
                    probeinfo_s.frame = cnt_frame2;
                    probe_info[station_s] = probeinfo_s;
                }else if(ret3.second == false){ //if exist
                    pwr_probe2 = probe_info.find(station_s)->second.pwr;
                    essid_probe2= probe_info.find(station_s)->second.probe;
                    cnt_frame2 = probe_info.find(station_s)->second.frame + 1; //frame count +1
                    probeinfo_s.pwr = pwr_probe2;
                    probeinfo_s.probe = essid_probe2;
                    probeinfo_s.frame = cnt_frame2;
                    probe_info[station_s] = probeinfo_s;
                }
            }


            //show beacon frame
            printf("no BSSID \t\t\t PWR\tCH\tBEACONS\tSSID\n");
            printf("=======================================================================================================\n");
            for(beacon_infoit = beacon_info.begin();beacon_infoit != beacon_info.end();beacon_infoit++){
                memcpy(char_beacon_bssid, &beacon_infoit->first, 6);
                printf("%d ",i);
                printf("%02x:%02x:%02x:%02x:%02x:%02x \t : \t",char_beacon_bssid[0],char_beacon_bssid[1],char_beacon_bssid[2],char_beacon_bssid[3],char_beacon_bssid[4],char_beacon_bssid[5]);
                printf("%d\t",beacon_infoit->second.pwr);
                printf("%d\t",beacon_infoit->second.Chanel);
                printf("%d\t",beacon_infoit->second.beacons);
                printf("%s\n",beacon_infoit->second.essid.c_str());
                i++;
            }
            //show probe reqeust, probe response
            printf("\n");
            printf("no BSSID \t\t\t STATION\t\t\tPWR\tFRAMES\tPROBE\n");
            printf("=======================================================================================================\n");
            for(probe_infoit = probe_info.begin();probe_infoit != probe_info.end();probe_infoit++){
                memcpy(char_probe_station, &probe_infoit->first, 6);
                memcpy(char_probe_bssid, &probe_infoit->second.bssidmac, 6);
                printf("%d ",j);
                if(char_probe_bssid[0]==0xff&&char_probe_bssid[1]==0xff&&char_probe_bssid[2]==0xff&&char_probe_bssid[3]==0xff&&char_probe_bssid[4]==0xff&&char_probe_bssid[5]==0xff){
                    printf("(not associated) \t : \t");
                }else{
                    printf("%02x:%02x:%02x:%02x:%02x:%02x \t : \t",char_probe_bssid[0],char_probe_bssid[1],char_probe_bssid[2],char_probe_bssid[3],char_probe_bssid[4],char_probe_bssid[5]);
                }
                printf("%02x:%02x:%02x:%02x:%02x:%02x \t : \t",char_probe_station[0],char_probe_station[1],char_probe_station[2],char_probe_station[3],char_probe_station[4],char_probe_station[5]);
                printf("%d\t",probe_infoit->second.pwr);
                printf("%d\t",probe_infoit->second.frame);
                printf("%s\n",probe_infoit->second.probe.c_str());
                j++;
            }
            printf("=======================================================================================================\n");

        }
        res = pcap_next_ex(handle, &header, &packet);
    }
    //Close
    pcap_close(handle);
    return 1;
}


