/**
 * @file ccndhcpclient.c
 * @brief Start DHCP client on local nodes
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

void get_dhcp_content(struct ccn *h)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_parsed_ContentObject pcobuf = {0};
    int res;
    const unsigned char *ptr;
    size_t length;
    struct ccn_dhcp_content *dc;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    res = ccn_get(h, name, NULL, 3000, resultbuf, &pcobuf, NULL, 0);
    if (res >= 0) {
        ptr = resultbuf->buf;
        length = resultbuf->length;
        ccn_content_get_value(ptr, length, &pcobuf, &ptr, &length);
        dc = ccn_dhcp_content_parse(ptr, length);
        printf("---%s---\n", dc->name_prefix->buf);
        printf("---%s---\n", dc->address);
        printf("---%s---\n", dc->port);
    }

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
    ccn_dhcp_content_destroy(&dc);
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
    get_dhcp_content(h);

    ccn_destroy(&h);
    exit(res < 0);
}
