#include "header/header.h"

int cmp_beacon(const u_char *cmp){
    if(cmp[0]+cmp[1] == 0x0080){
        return 1;
    }
    else {
        return 0;
    }
}
int cmp_probereq(const u_char *cmp){
    if(cmp[0] == 0x40){
        return 1;
    }
    else {
        return 0;
    }
}
int cmp_proberes(const u_char *cmp){
    if(cmp[0] == 0x50){
        return 1;
    }
    else {
        return 0;
    }
}
