/**
 * @file ccndhcpserver.c
 * @brief Start DHCP server on the gateway
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/charbuf.h>
#include <ccn/ccn_dhcp.h>

void put_dhcp_content(struct ccn *h)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    char buf[] = "this is a test string";
    int res;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    sp.type = CCN_CONTENT_DATA;

    res = ccn_sign_content(h, resultbuf, name, &sp, buf, strlen(buf));
    if (res != 0) {
        fprintf(stderr, "Failed to encode ContentObject (res == %d)\n", res);
        exit(1);
    }

    res = ccn_put(h, resultbuf->buf, resultbuf->length);
    if (res < 0) {
        fprintf(stderr, "ccn_put failed (res == %d)\n", res);
        exit(1);
    }

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
}

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

    join_dhcp_group(h);
    put_dhcp_content(h);

    ccn_destroy(&h);
    exit(res < 0);
}
