/*
 * @file ccn_dhcp.h
 */

#define CCN_DHCP_URI "ccnx:/local/dhcp"
#define CCN_DHCP_CONTENT_URI "ccnx:/local/dhcp/content"
#define CCN_DHCP_ADDR "224.0.0.66"
#define CCN_DHCP_PORT "60006"
#define CCN_DHCP_LIFETIME ((~0U) >> 1)
#define CCN_DHCP_MCASTTTL (-1)

void join_dhcp_group(struct ccn *h);
