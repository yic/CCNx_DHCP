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
#include <errno.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/charbuf.h>
#include <ccn/ccn_dhcp.h>

struct ccn_dhcp_content *read_config_file(const char *filename)
{
    char *uri;
    char *host;
    char *port;
    FILE *cfg;
    char buf[1024];
    int len;
    char *cp;
    char *last = NULL;
    const char *seps = " \t\n";
    struct ccn_dhcp_content *result = calloc(1, sizeof(*result));

    cfg = fopen(filename, "r");
    if (cfg == NULL) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        exit(1);
    }

    while (fgets((char *)buf, sizeof(buf), cfg)) {
        len = strlen(buf);
        if (buf[0] == '#' || len == 0)
            continue;

        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        cp = index(buf, '#');
        if (cp != NULL)
            *cp = '\0';

        uri = strtok_r(buf, seps, &last);
        if (uri == NULL)    /* blank line */
            continue;

        host = strtok_r(NULL, seps, &last);
        port = strtok_r(NULL, seps, &last);

        result->name_prefix = ccn_charbuf_create();
        ccn_name_from_uri(result->name_prefix, uri);
        result->address = host;
        result->port = port;
        break;
    }

    fclose(cfg);

    return result;
}

void put_dhcp_content(struct ccn *h)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    struct ccn_charbuf *body = ccn_charbuf_create();
    struct ccn_dhcp_content *dc;
    int res;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    sp.type = CCN_CONTENT_DATA;

    dc = read_config_file(CCN_DHCP_CONFIG);
    ccnb_append_dhcp_content(body, dc);

    res = ccn_sign_content(h, resultbuf, name, &sp, body->buf, body->length);
    if (res != 0) {
        fprintf(stderr, "Failed to encode ContentObject (res == %d)\n", res);
        exit(1);
    }

    res = ccn_put(h, resultbuf->buf, resultbuf->length);
    if (res < 0) {
        fprintf(stderr, "ccn_put failed (res == %d)\n", res);
        exit(1);
    }

    ccn_charbuf_destroy(&body);
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
    put_dhcp_content(h);

    ccn_destroy(&h);
    exit(res < 0);
}
