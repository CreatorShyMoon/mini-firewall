#ifndef _MINI_FIREWALL_H_
#define _MINI_FIREWALL_H_

#include <linux/types.h>

#define MFW_MODULE_NAME       "mini_firewall"
#define MFW_PROC_NAME         "mini_firewall"
#define MFW_MAX_RULES         64
#define MFW_MAX_CMD_LEN       128

/* Rule types */
enum mfw_rule_type {
    MFW_RULE_IP_SRC,
    MFW_RULE_IP_DST,
    MFW_RULE_PORT_TCP,
    MFW_RULE_PORT_UDP,
    MFW_RULE_PROTO
};

/* Filter Rule definition */
struct mfw_rule {
    enum mfw_rule_type type;
    __be32 ip;             /* IPv4 address in network byte order */
    __u16 port;            /* Port number in host byte order */
    __u8 proto;            /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    __u64 hit_count;       /* Number of times this rule matched */
    char desc[32];         /* Human readable description */
};

/* Firewall Statistics */
struct mfw_stats {
    __u64 pkts_processed;
    __u64 pkts_accepted;
    __u64 pkts_dropped;
    __u64 bytes_dropped;
    __u64 drops_by_ip;
    __u64 drops_by_port;
    __u64 drops_by_proto;
    __u64 drops_by_scan;
};

#endif /* _MINI_FIREWALL_H_ */
