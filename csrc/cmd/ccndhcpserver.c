/**
 * @file ccndhcpserver.c
 * @brief Start DHCP server on the gateway
 */
#include <stdio.h>
#include <stdlib.h>
#include <ccn/ccn.h>

int main(int argc, char **argv)
{
    struct ccn *h = NULL;
    int res;

    h = ccn_create();
    res = ccn_connect(h, NULL);
    if (res < 0) {
        ccn_perror(h, "ccn_connect");
        exit(1);
    }

    exit(0);
}
