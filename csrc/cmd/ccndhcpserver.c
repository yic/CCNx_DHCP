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

static void usage(const char *progname)
{
    fprintf(stderr,
            "%s [-f config_file]\n"
            "./ccn_dhcp.config is read by default if no config file is specified\n"
            , progname);
    exit(1);
}

int read_config_file(const char *filename, struct ccn_dhcp_entry *tail)
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
    struct ccn_dhcp_entry *de = tail;
    int count = 0;
    int res = 0;

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

        de->next = calloc(1, sizeof(*de));
        de = de->next;
        memset(de, 0, sizeof(*de));
        de->next = NULL;
        de->store = NULL;

        host = strtok_r(NULL, seps, &last);
        port = strtok_r(NULL, seps, &last);

        de->name_prefix = ccn_charbuf_create();
        res = ccn_name_from_uri(de->name_prefix, uri);
        if (res < 0) {
            fprintf(stderr, "Bad URI format: %s\n", uri);
            exit(1);
        }

        memcpy((void *)de->address, host, strlen(host));
        memcpy((void *)de->port, port, strlen(port));

        count ++;
    }

    fclose(cfg);

    return count;
}

/*
 * Publish DHCP content
 */
int put_dhcp_content(struct ccn *h, const char *config_file)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_charbuf *resultbuf = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    struct ccn_charbuf *body = ccn_charbuf_create();
    struct ccn_dhcp_entry de_storage = {0};
    struct ccn_dhcp_entry *de = &de_storage;
    int entry_count;
    int res;

    ccn_name_from_uri(name, CCN_DHCP_CONTENT_URI);
    sp.type = CCN_CONTENT_DATA;

    entry_count = read_config_file(config_file, de);

    res = ccnb_append_dhcp_content(body, entry_count, de->next);
    if (res < 0) {
        fprintf(stderr, "Error appending DHCP content.\n");
        goto cleanup;
    }

    res = ccn_sign_content(h, resultbuf, name, &sp, body->buf, body->length);
    if (res < 0) {
        fprintf(stderr, "Failed to encode ContentObject.\n");
        goto cleanup;
    }

    res = ccn_put(h, resultbuf->buf, resultbuf->length);
    if (res < 0) {
        fprintf(stderr, "ccn_put failed.\n");
        goto cleanup;
    }

    ccn_charbuf_destroy(&body);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
    ccn_dhcp_content_destroy(de->next);

    return 0;
cleanup:
    ccn_charbuf_destroy(&body);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
    ccn_dhcp_content_destroy(de->next);

    return -1;
}

int main(int argc, char **argv)
{
    struct ccn *h = NULL;
    int res;
    const char *config_file = CCN_DHCP_CONFIG;

    while ((res = getopt(argc, argv, "f:h")) != -1) {
        switch (res) {
            case 'f':
                config_file = optarg;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }

    h = ccn_create();
    res = ccn_connect(h, NULL);
    if (res < 0) {
        ccn_perror(h, "Cannot connect to ccnd.");
        exit(1);
    }

    res = join_dhcp_group(h);
    if (res < 0) {
        ccn_perror(h, "Cannot join DHCP group.");
        exit(1);
    }

    res = put_dhcp_content(h, config_file);
    if (res < 0) {
        ccn_perror(h, "Cannot publish DHCP content.");
        exit(1);
    }

    ccn_destroy(&h);
    exit(res < 0);
}
