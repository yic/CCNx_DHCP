/**
 * @file ccndhcp.c
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
#include <ccn/face_mgmt.h>
#include <ccn/reg_mgmt.h>
#include <ccn/charbuf.h>
#include <ccn/ccn_dhcp.h>

int register_prefix(struct ccn *h, struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name, struct ccn_charbuf *name_prefix,
        struct ccn_face_instance *face_instance)
{
    struct ccn_charbuf *temp = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_charbuf *signed_info = NULL;
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *prefixreg = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    struct ccn_forwarding_entry forwarding_entry_storage = {0};
    struct ccn_forwarding_entry *forwarding_entry = &forwarding_entry_storage;
    struct ccn_forwarding_entry *new_forwarding_entry;
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res;

    /* Register or unregister the prefix */
    forwarding_entry->action = "prefixreg";
    forwarding_entry->name_prefix = name_prefix;
    forwarding_entry->ccnd_id = face_instance->ccnd_id;
    forwarding_entry->ccnd_id_size = face_instance->ccnd_id_size;
    forwarding_entry->faceid = face_instance->faceid;
    forwarding_entry->flags = -1;
    forwarding_entry->lifetime = (~0U) >> 1;

    prefixreg = ccn_charbuf_create();
    ccnb_append_forwarding_entry(prefixreg, forwarding_entry);
    temp = ccn_charbuf_create();
    res = ccn_sign_content(h, temp, no_name, NULL, prefixreg->buf, prefixreg->length);
    resultbuf = ccn_charbuf_create();

    name = ccn_charbuf_create();
    ccn_name_init(name);
    ccn_name_append_str(name, "ccnx");
    ccn_name_append(name, face_instance->ccnd_id, face_instance->ccnd_id_size);
    ccn_name_append_str(name, "prefixreg");
    ccn_name_append(name, temp->buf, temp->length);

    res = ccn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
    ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
    new_forwarding_entry = ccn_forwarding_entry_parse(ptr, length);

    res = new_forwarding_entry->faceid;

    ccn_forwarding_entry_destroy(&new_forwarding_entry);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&prefixreg);

    return (res);
}

struct ccn_face_instance *create_face(struct ccn *h, struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name, struct ccn_face_instance *face_instance)
{
    struct ccn_charbuf *newface = NULL;
    struct ccn_charbuf *signed_info = NULL;
    struct ccn_charbuf *temp = NULL;
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    struct ccn_face_instance *new_face_instance = NULL;
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res = 0;

    /* Encode the given face instance */
    newface = ccn_charbuf_create();
    ccnb_append_face_instance(newface, face_instance);

    temp = ccn_charbuf_create();
    res = ccn_sign_content(h, temp, no_name, NULL, newface->buf, newface->length);
    resultbuf = ccn_charbuf_create();

    /* Construct the Interest name that will create the face */
    name = ccn_charbuf_create();
    ccn_name_init(name);
    ccn_name_append_str(name, "ccnx");
    ccn_name_append(name, face_instance->ccnd_id, face_instance->ccnd_id_size);
    ccn_name_append_str(name, face_instance->action);
    ccn_name_append(name, temp->buf, temp->length);
    res = ccn_get(h, name, local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);

    ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length);
    new_face_instance = ccn_face_instance_parse(ptr, length);

    ccn_charbuf_destroy(&newface);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&temp);
    ccn_charbuf_destroy(&resultbuf);
    ccn_charbuf_destroy(&name);
    return (new_face_instance);
}

static int get_ccndid(struct ccn *h, struct ccn_charbuf *local_scope_template,
        const unsigned char *ccndid, size_t ccndid_storage_size)
{
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *resultbuf = NULL;
    struct ccn_parsed_ContentObject pcobuf = {0};
    char ccndid_uri[] = "ccnx:/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY";
    const unsigned char *ccndid_result;
    static size_t ccndid_result_size;

    name = ccn_charbuf_create();
    resultbuf = ccn_charbuf_create();

    ccn_name_from_uri(name, ccndid_uri);
    ccn_get(h, name, local_scope_template, 4500, resultbuf, &pcobuf, NULL, 0);

    ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest,
            resultbuf->buf,
            pcobuf.offset[CCN_PCO_B_PublisherPublicKeyDigest],
            pcobuf.offset[CCN_PCO_E_PublisherPublicKeyDigest],
            &ccndid_result, &ccndid_result_size);

    memcpy((void *)ccndid, ccndid_result, ccndid_result_size);

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);

    return (ccndid_result_size);
}

struct ccn_face_instance *construct_face(const unsigned char *ccndid, size_t ccndid_size)
{
    struct ccn_face_instance *fi = calloc(1, sizeof(*fi));
    char rhostnamebuf[NI_MAXHOST];
    char rhostportbuf[NI_MAXSERV];
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG),
        .ai_socktype = SOCK_DGRAM};
    struct addrinfo *raddrinfo = NULL;
    struct ccn_charbuf *store = ccn_charbuf_create();
    int host_off = -1;
    int port_off = -1;

    getaddrinfo(CCN_DHCP_ADDR, CCN_DHCP_PORT, &hints, &raddrinfo);
    getnameinfo(raddrinfo->ai_addr, raddrinfo->ai_addrlen,
            rhostnamebuf, sizeof(rhostnamebuf),
            rhostportbuf, sizeof(rhostportbuf),
            NI_NUMERICHOST | NI_NUMERICSERV);
    freeaddrinfo(raddrinfo);

    fi->store = store;
    fi->descr.ipproto = IPPROTO_UDP;
    fi->descr.mcast_ttl = CCN_DHCP_MCASTTTL;
    fi->lifetime = CCN_DHCP_LIFETIME;

    ccn_charbuf_append(store, "newface", strlen("newface") + 1);
    host_off = store->length;
    ccn_charbuf_append(store, CCN_DHCP_ADDR, strlen(CCN_DHCP_ADDR) + 1);
    port_off = store->length;
    ccn_charbuf_append(store, CCN_DHCP_PORT, strlen(CCN_DHCP_PORT) + 1);

    char *b = (char *)store->buf;
    fi->action = b;
    fi->descr.address = b + host_off;
    fi->descr.port = b + port_off;
    fi->descr.source_address = NULL;
    fi->ccnd_id = ccndid;
    fi->ccnd_id_size = ccndid_size;

    return fi;
}

void init_data(struct ccn_charbuf *local_scope_template,
        struct ccn_charbuf *no_name)
{
    ccn_charbuf_append_tt(local_scope_template, CCN_DTAG_Interest, CCN_DTAG);
    ccn_charbuf_append_tt(local_scope_template, CCN_DTAG_Name, CCN_DTAG);
    ccn_charbuf_append_closer(local_scope_template);
    ccnb_tagged_putf(local_scope_template, CCN_DTAG_Scope, "1");
    ccn_charbuf_append_closer(local_scope_template);

    ccn_name_init(no_name);
}

void join_dhcp_group(struct ccn *h)
{
    struct ccn_charbuf *local_scope_template = ccn_charbuf_create();
    struct ccn_charbuf *no_name = ccn_charbuf_create();
    struct ccn_charbuf *prefix = ccn_charbuf_create();
    unsigned char ccndid_storage[32] = {0};
    const unsigned char *ccndid = ccndid_storage;
    size_t ccndid_size = 0;
    struct ccn_face_instance *fi;
    struct ccn_face_instance *nfi;

    init_data(local_scope_template, no_name);
    ccn_name_from_uri(prefix, CCN_DHCP_URI);

    ccndid_size = get_ccndid(h, local_scope_template, ccndid, sizeof(ccndid_storage));
    fi = construct_face(ccndid, ccndid_size);
    nfi = create_face(h, local_scope_template, no_name, fi);
    register_prefix(h, local_scope_template, no_name, prefix, nfi);

    ccn_charbuf_destroy(&local_scope_template);
    ccn_charbuf_destroy(&no_name);
    ccn_charbuf_destroy(&prefix);
    ccn_face_instance_destroy(&fi);
    ccn_face_instance_destroy(&nfi);
}

struct ccn_dhcp_content *ccn_dhcp_content_parse(const unsigned char *p, size_t size)
{
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = ccn_buf_decoder_start(&decoder, p, size);
    struct ccn_charbuf *store = ccn_charbuf_create();
    struct ccn_dhcp_content *result = calloc(1, sizeof(*result));
    size_t start;
    size_t end;
    int host_off = -1;
    int port_off = -1;

    result->store = store;

    if (ccn_buf_match_dtag(d, CCN_DTAG_DHCPContent)) {
        ccn_buf_advance(d);
//      if (ccn_buf_match_dtag(d, CCN_DTAG_Name)) {
//          result->name_prefix = ccn_charbuf_create();
//          start = d->decoder.token_index;
//          ccn_parse_Name(d, NULL);
//          end = d->decoder.token_index;
//          ccn_charbuf_append(result->name_prefix, p + start, end - start);
//      }
//      else
//          result->name_prefix = NULL;

        host_off = ccn_parse_tagged_string(d, CCN_DTAG_Host, store);
        port_off = ccn_parse_tagged_string(d, CCN_DTAG_Port, store);
    }
    else
        d->decoder.state = -__LINE__;

    if (d->decoder.index != size || !CCN_FINAL_DSTATE(d->decoder.state))
        ccn_dhcp_content_destroy(&result);
    else {
        char *b = (char *)store->buf;
        result->address = (host_off == -1) ? NULL : b + host_off;
        result->port = (port_off == -1) ? NULL : b + port_off;
    }

    return result;
}

void ccn_dhcp_content_destroy(struct ccn_dhcp_content **dc)
{
    if (*dc != NULL) {
        ccn_charbuf_destroy(&(*dc)->name_prefix);
        ccn_charbuf_destroy(&(*dc)->store);
        free(*dc);
        *dc = NULL;
    }
}

int ccnb_append_dhcp_content(struct ccn_charbuf *c, const struct ccn_dhcp_content *dc)
{
    int res;
    res = ccnb_element_begin(c, CCN_DTAG_DHCPContent);

//  if (dc->name_prefix != NULL && dc->name_prefix->length > 0)
//      res |= ccn_charbuf_append(c, dc->name_prefix->buf, dc->name_prefix->length);

    if (dc->address != NULL)
        res |= ccnb_tagged_putf(c, CCN_DTAG_Host, "%s", dc->address);
    if (dc->port != NULL)
        res |= ccnb_tagged_putf(c, CCN_DTAG_Port, "%s", dc->port);

    res |= ccnb_element_end(c);
    return res;
}

