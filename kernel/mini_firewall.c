// SPDX-License-Identifier: GPL-2.0
/*
 * mini-firewall - High Performance Netfilter LKM Packet Filter & Security Monitor
 * Author: Albert Adamyan <albertadaman70@gmail.com>
 *
 * Intercepts network packets at NF_INET_PRE_ROUTING hook, performs fast
 * rule matching (IP, Port, Protocol, TCP Anomaly/PortScan detection),
 * and provides runtime telemetry & management via /proc/mini_firewall.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/string.h>

#include "mini_firewall.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Albert Adamyan");
MODULE_DESCRIPTION("Stateful Netfilter LKM Packet Filter & Security Monitor");
MODULE_VERSION("1.0.0");

/* Global state */
static struct mfw_rule rules[MFW_MAX_RULES];
static unsigned int rule_count = 0;
static struct mfw_stats stats = {0};
static bool scan_detection_enabled = true;

/* Spinlock protects rules table and stats under softirq (BH) context */
static DEFINE_SPINLOCK(mfw_lock);

/* Netfilter hook options */
static struct nf_hook_ops nf_ops;

/* Proc entry pointer */
static struct proc_dir_entry *proc_entry = NULL;

/*
 * Helper: Check for suspicious TCP flag combinations (port scans)
 * - NULL scan: No flags set
 * - Xmas scan: FIN, PSH, and URG set
 * - SYN-FIN scan: Both SYN and FIN set
 */
static bool is_tcp_scan_packet(const struct tcphdr *tcph)
{
    /* NULL scan */
    if (!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg)
        return true;

    /* Xmas scan */
    if (tcph->fin && tcph->psh && tcph->urg)
        return true;

    /* SYN-FIN scan */
    if (tcph->syn && tcph->fin)
        return true;

    return false;
}

/*
 * Netfilter Packet Inspection Hook Function
 * Triggered for all incoming IPv4 packets at NF_INET_PRE_ROUTING
 */
static unsigned int mfw_hook_fn(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    unsigned int action = NF_ACCEPT;
    unsigned int i;
    __u16 dest_port = 0;
    __u8 protocol;
    __be32 src_ip, dst_ip;

    if (unlikely(!skb))
        return NF_ACCEPT;

    /* Extract IPv4 Header */
    iph = ip_hdr(skb);
    if (unlikely(!iph))
        return NF_ACCEPT;

    src_ip = iph->saddr;
    dst_ip = iph->daddr;
    protocol = iph->protocol;

    /* Extract Transport Layer Headers */
    if (protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (tcph)
            dest_port = ntohs(tcph->dest);
    } else if (protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (udph)
            dest_port = ntohs(udph->dest);
    } else if (protocol == IPPROTO_ICMP) {
        icmph = icmp_hdr(skb);
    }

    spin_lock_bh(&mfw_lock);
    stats.pkts_processed++;

    /* 1. Anomaly & Port Scan Detection */
    if (scan_detection_enabled && protocol == IPPROTO_TCP && tcph) {
        if (unlikely(is_tcp_scan_packet(tcph))) {
            stats.pkts_dropped++;
            stats.bytes_dropped += skb->len;
            stats.drops_by_scan++;
            spin_unlock_bh(&mfw_lock);

            pr_warn_ratelimited("mini_firewall: [ALERT] TCP PortScan / Anomaly detected from %pI4! Packet dropped.\n",
                                &src_ip);
            return NF_DROP;
        }
    }

    /* 2. Match against active rules */
    for (i = 0; i < rule_count; i++) {
        struct mfw_rule *r = &rules[i];

        switch (r->type) {
        case MFW_RULE_IP_SRC:
            if (src_ip == r->ip) {
                r->hit_count++;
                stats.drops_by_ip++;
                action = NF_DROP;
            }
            break;

        case MFW_RULE_IP_DST:
            if (dst_ip == r->ip) {
                r->hit_count++;
                stats.drops_by_ip++;
                action = NF_DROP;
            }
            break;

        case MFW_RULE_PORT_TCP:
            if (protocol == IPPROTO_TCP && dest_port == r->port) {
                r->hit_count++;
                stats.drops_by_port++;
                action = NF_DROP;
            }
            break;

        case MFW_RULE_PORT_UDP:
            if (protocol == IPPROTO_UDP && dest_port == r->port) {
                r->hit_count++;
                stats.drops_by_port++;
                action = NF_DROP;
            }
            break;

        case MFW_RULE_PROTO:
            if (protocol == r->proto) {
                r->hit_count++;
                stats.drops_by_proto++;
                action = NF_DROP;
            }
            break;
        }

        if (action == NF_DROP) {
            stats.pkts_dropped++;
            stats.bytes_dropped += skb->len;
            spin_unlock_bh(&mfw_lock);

            pr_info_ratelimited("mini_firewall: [DROP] Rule #%u matched: src=%pI4 dst=%pI4 proto=%u port=%u\n",
                                i + 1, &src_ip, &dst_ip, protocol, dest_port);
            return NF_DROP;
        }
    }

    stats.pkts_accepted++;
    spin_unlock_bh(&mfw_lock);

    return NF_ACCEPT;
}

/*
 * Procfs Read Callback: Outputs human-readable status, stats, and rule table
 */
static ssize_t mfw_proc_read(struct file *file, char __user *user_buf,
                             size_t count, loff_t *ppos)
{
    char *buf;
    int len = 0;
    ssize_t ret;
    unsigned int i;

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    spin_lock_bh(&mfw_lock);

    len += scnprintf(buf + len, 4096 - len,
                     "=== mini-firewall (Stateful Netfilter LKM Firewall) ===\n"
                     "Version: 1.0.0\n"
                     "Hook stage: NF_INET_PRE_ROUTING\n"
                     "Scan detection: %s\n\n",
                     scan_detection_enabled ? "ENABLED" : "DISABLED");

    len += scnprintf(buf + len, 4096 - len,
                     "--- Statistics ---\n"
                     "Total Processed: %llu\n"
                     "Accepted:        %llu\n"
                     "Dropped:         %llu\n"
                     "Dropped Bytes:   %llu bytes\n"
                     "  - Drops by IP:       %llu\n"
                     "  - Drops by Port:     %llu\n"
                     "  - Drops by Protocol: %llu\n"
                     "  - Drops by Scan:     %llu\n\n",
                     stats.pkts_processed,
                     stats.pkts_accepted,
                     stats.pkts_dropped,
                     stats.bytes_dropped,
                     stats.drops_by_ip,
                     stats.drops_by_port,
                     stats.drops_by_proto,
                     stats.drops_by_scan);

    len += scnprintf(buf + len, 4096 - len,
                     "--- Active Rules (%u/%d) ---\n", rule_count, MFW_MAX_RULES);

    if (rule_count == 0) {
        len += scnprintf(buf + len, 4096 - len, "  (No active rules. All traffic allowed)\n");
    } else {
        for (i = 0; i < rule_count; i++) {
            struct mfw_rule *r = &rules[i];
            switch (r->type) {
            case MFW_RULE_IP_SRC:
                len += scnprintf(buf + len, 4096 - len,
                                 "  [%u] BLOCK SRC IP:   %pI4 (Hits: %llu)\n",
                                 i + 1, &r->ip, r->hit_count);
                break;
            case MFW_RULE_IP_DST:
                len += scnprintf(buf + len, 4096 - len,
                                 "  [%u] BLOCK DST IP:   %pI4 (Hits: %llu)\n",
                                 i + 1, &r->ip, r->hit_count);
                break;
            case MFW_RULE_PORT_TCP:
                len += scnprintf(buf + len, 4096 - len,
                                 "  [%u] BLOCK TCP PORT: %u (Hits: %llu)\n",
                                 i + 1, r->port, r->hit_count);
                break;
            case MFW_RULE_PORT_UDP:
                len += scnprintf(buf + len, 4096 - len,
                                 "  [%u] BLOCK UDP PORT: %u (Hits: %llu)\n",
                                 i + 1, r->port, r->hit_count);
                break;
            case MFW_RULE_PROTO:
                len += scnprintf(buf + len, 4096 - len,
                                 "  [%u] BLOCK PROTO:    %s (%u) (Hits: %llu)\n",
                                 i + 1,
                                 r->proto == IPPROTO_ICMP ? "ICMP (ping)" :
                                 r->proto == IPPROTO_TCP ? "TCP" :
                                 r->proto == IPPROTO_UDP ? "UDP" : "OTHER",
                                 r->proto, r->hit_count);
                break;
            }
        }
    }

    len += scnprintf(buf + len, 4096 - len, "==================================================\n");

    spin_unlock_bh(&mfw_lock);

    ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
    kfree(buf);
    return ret;
}

/*
 * Procfs Write Callback: Parses management commands from User Space
 */
static ssize_t mfw_proc_write(struct file *file, const char __user *user_buf,
                              size_t count, loff_t *ppos)
{
    char kbuf[MFW_MAX_CMD_LEN];
    char cmd[32], arg1[64], arg2[32];
    int ntokens;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, user_buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (count > 0 && kbuf[count - 1] == '\n')
        kbuf[count - 1] = '\0';

    cmd[0] = arg1[0] = arg2[0] = '\0';
    ntokens = sscanf(kbuf, "%31s %63s %31s", cmd, arg1, arg2);

    if (ntokens < 1)
        return -EINVAL;

    spin_lock_bh(&mfw_lock);

    if (strcmp(cmd, "clear") == 0) {
        rule_count = 0;
        pr_info("mini_firewall: all rules cleared.\n");
    } else if (strcmp(cmd, "reset_stats") == 0) {
        memset(&stats, 0, sizeof(stats));
        pr_info("mini_firewall: statistics reset.\n");
    } else if (strcmp(cmd, "detect_scans") == 0 && ntokens >= 2) {
        scan_detection_enabled = (arg1[0] == '1' || strcmp(arg1, "on") == 0);
        pr_info("mini_firewall: scan detection set to %d\n", scan_detection_enabled);
    } else if (strcmp(cmd, "block_ip") == 0 && ntokens >= 2) {
        if (rule_count < MFW_MAX_RULES) {
            __be32 ip_val;
            if (in4_pton(arg1, -1, (u8 *)&ip_val, -1, NULL) > 0) {
                rules[rule_count].type = MFW_RULE_IP_SRC;
                rules[rule_count].ip = ip_val;
                rules[rule_count].hit_count = 0;
                snprintf(rules[rule_count].desc, sizeof(rules[rule_count].desc), "IP: %s", arg1);
                rule_count++;
                pr_info("mini_firewall: blocked IP %s\n", arg1);
            } else {
                pr_err("mini_firewall: invalid IP format: %s\n", arg1);
            }
        }
    } else if (strcmp(cmd, "block_port") == 0 && ntokens >= 2) {
        if (rule_count < MFW_MAX_RULES) {
            unsigned int port_val;
            if (kstrtouint(arg1, 10, &port_val) == 0 && port_val <= 65535) {
                rules[rule_count].type = MFW_RULE_PORT_TCP;
                if (ntokens >= 3 && strcmp(arg2, "udp") == 0)
                    rules[rule_count].type = MFW_RULE_PORT_UDP;

                rules[rule_count].port = (__u16)port_val;
                rules[rule_count].hit_count = 0;
                rule_count++;
                pr_info("mini_firewall: blocked port %u\n", port_val);
            }
        }
    } else if (strcmp(cmd, "block_proto") == 0 && ntokens >= 2) {
        if (rule_count < MFW_MAX_RULES) {
            rules[rule_count].type = MFW_RULE_PROTO;
            rules[rule_count].hit_count = 0;

            if (strcmp(arg1, "icmp") == 0) {
                rules[rule_count].proto = IPPROTO_ICMP;
                rule_count++;
                pr_info("mini_firewall: blocked protocol ICMP (ping drop)\n");
            } else if (strcmp(arg1, "tcp") == 0) {
                rules[rule_count].proto = IPPROTO_TCP;
                rule_count++;
                pr_info("mini_firewall: blocked protocol TCP\n");
            } else if (strcmp(arg1, "udp") == 0) {
                rules[rule_count].proto = IPPROTO_UDP;
                rule_count++;
                pr_info("mini_firewall: blocked protocol UDP\n");
            }
        }
    } else {
        pr_warn("mini_firewall: unknown command '%s'\n", cmd);
    }

    spin_unlock_bh(&mfw_lock);
    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops mfw_proc_fops = {
    .proc_read  = mfw_proc_read,
    .proc_write = mfw_proc_write,
};
#else
static const struct file_operations mfw_proc_fops = {
    .owner = THIS_MODULE,
    .read  = mfw_proc_read,
    .write = mfw_proc_write,
};
#endif

static int __init mfw_init(void)
{
    int ret;

    pr_info("mini_firewall: initializing Netfilter LKM Packet Filter v1.0.0...\n");

    proc_entry = proc_create(MFW_PROC_NAME, 0666, NULL, &mfw_proc_fops);
    if (!proc_entry) {
        pr_err("mini_firewall: failed to create /proc/%s\n", MFW_PROC_NAME);
        return -ENOMEM;
    }

    nf_ops.hook     = mfw_hook_fn;
    nf_ops.hooknum  = NF_INET_PRE_ROUTING;
    nf_ops.pf       = PF_INET;
    nf_ops.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nf_ops);
    if (ret < 0) {
        pr_err("mini_firewall: failed to register Netfilter hook (err=%d)\n", ret);
        proc_remove(proc_entry);
        return ret;
    }

    pr_info("mini_firewall: Netfilter hook registered at NF_INET_PRE_ROUTING successfully.\n");
    pr_info("mini_firewall: Control interface active at /proc/%s\n", MFW_PROC_NAME);
    return 0;
}

static void __exit mfw_exit(void)
{
    pr_info("mini_firewall: unloading module...\n");

    nf_unregister_net_hook(&init_net, &nf_ops);

    if (proc_entry)
        proc_remove(proc_entry);

    pr_info("mini_firewall: module unloaded cleanly.\n");
}

module_init(mfw_init);
module_exit(mfw_exit);
