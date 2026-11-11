/*
 * fwctl - kfirewall User Space Command Line Management Tool
 * Author: Albert Adamyan <albertadaman70@gmail.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>

#define PROC_PATH "/proc/mini_firewall"

#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"

static void print_banner(void)
{
    printf("%s%s", COLOR_CYAN, COLOR_BOLD);
    printf("┌────────────────────────────────────────────────────────┐\n");
    printf("│   mini-firewall CLI (v1.0.0) - Linux Kernel Filter     │\n");
    printf("│   Author: Albert Adamyan                               │\n");
    printf("└────────────────────────────────────────────────────────┘\n");
    printf("%s", COLOR_RESET);
}

static void print_help(const char *progname)
{
    print_banner();
    printf("%sUSAGE:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s <command> [arguments]\n\n", progname);

    printf("%sCOMMANDS:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %sstatus%s                Show firewall state, packet stats, and active rules\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sblock ip <ip>%s         Block incoming packets from source IP\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sblock port <n> [proto]%s Block destination port (default: tcp)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sblock proto <proto>%s   Block protocol: icmp (ping), tcp, or udp\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sscan-detect <on|off>%s  Toggle TCP port scan / anomaly detector\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sclear%s                 Remove all active firewall rules\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sreset-stats%s           Reset packet counters to zero\n", COLOR_GREEN, COLOR_RESET);
    printf("  %smonitor%s               Live real-time packet telemetry loop\n", COLOR_GREEN, COLOR_RESET);
    printf("  %shelp%s                  Display this help message\n\n", COLOR_GREEN, COLOR_RESET);

    printf("%sEXAMPLES:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  sudo %s block ip 192.168.1.100\n", progname);
    printf("  sudo %s block port 8080 tcp\n", progname);
    printf("  sudo %s block proto icmp\n", progname);
    printf("  sudo %s scan-detect on\n", progname);
    printf("  %s status\n", progname);
}

static int check_module_loaded(void)
{
    if (access(PROC_PATH, F_OK) != 0) {
        fprintf(stderr, "%s[ERROR]%s mini_firewall kernel module is not loaded!\n", COLOR_RED, COLOR_RESET);
        fprintf(stderr, "Hint: Run 'sudo insmod kernel/mini_firewall.ko' or 'sudo make load'\n");
        return -1;
    }
    return 0;
}

static int show_status(void)
{
    if (check_module_loaded() < 0)
        return 1;

    FILE *f = fopen(PROC_PATH, "r");
    if (!f) {
        perror("fopen " PROC_PATH);
        return 1;
    }

    char line[512];
    print_banner();

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "=== mini-firewall")) {
            printf("%s%s%s", COLOR_BOLD, COLOR_BLUE, line);
        } else if (strstr(line, "--- Statistics ---") || strstr(line, "--- Active Rules")) {
            printf("%s%s%s", COLOR_BOLD, COLOR_YELLOW, line);
        } else if (strstr(line, "Dropped:") || strstr(line, "Drops by")) {
            printf("%s%s%s", COLOR_RED, line, COLOR_RESET);
        } else if (strstr(line, "Accepted:")) {
            printf("%s%s%s", COLOR_GREEN, line, COLOR_RESET);
        } else if (strstr(line, "BLOCK")) {
            printf("%s%s%s", COLOR_RED, line, COLOR_RESET);
        } else {
            printf("%s", line);
        }
    }

    printf("%s", COLOR_RESET);
    fclose(f);
    return 0;
}

static int send_command(const char *cmd)
{
    if (check_module_loaded() < 0)
        return 1;

    int fd = open(PROC_PATH, O_WRONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            fprintf(stderr, "%s[ERROR]%s Permission denied. Run with sudo!\n", COLOR_RED, COLOR_RESET);
        } else {
            perror("open " PROC_PATH);
        }
        return 1;
    }

    size_t len = strlen(cmd);
    ssize_t written = write(fd, cmd, len);
    close(fd);

    if (written < 0) {
        perror("write to " PROC_PATH);
        return 1;
    }

    printf("%s[SUCCESS]%s Command applied: '%s'\n", COLOR_GREEN, COLOR_RESET, cmd);
    return 0;
}

static int monitor_loop(void)
{
    if (check_module_loaded() < 0)
        return 1;

    printf("\033[2J"); /* Clear screen */
    while (1) {
        printf("\033[H"); /* Cursor to top */
        show_status();
        printf("\n%sPress Ctrl+C to exit monitoring mode...%s\n", COLOR_YELLOW, COLOR_RESET);
        sleep(1);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help(argv[0]);
        return 0;
    }

    const char *action = argv[1];

    if (strcmp(action, "status") == 0) {
        return show_status();
    } else if (strcmp(action, "monitor") == 0) {
        return monitor_loop();
    } else if (strcmp(action, "clear") == 0) {
        return send_command("clear");
    } else if (strcmp(action, "reset-stats") == 0) {
        return send_command("reset_stats");
    } else if (strcmp(action, "scan-detect") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s scan-detect <on|off>\n", argv[0]);
            return 1;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "detect_scans %s", argv[2]);
        return send_command(buf);
    } else if (strcmp(action, "block") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  %s block ip <ip_address>\n", argv[0]);
            fprintf(stderr, "  %s block port <port_number> [tcp|udp]\n", argv[0]);
            fprintf(stderr, "  %s block proto <icmp|tcp|udp>\n", argv[0]);
            return 1;
        }

        const char *target = argv[2];
        const char *val = argv[3];
        char buf[128];

        if (strcmp(target, "ip") == 0) {
            snprintf(buf, sizeof(buf), "block_ip %s", val);
            return send_command(buf);
        } else if (strcmp(target, "port") == 0) {
            const char *proto = (argc >= 5) ? argv[4] : "tcp";
            snprintf(buf, sizeof(buf), "block_port %s %s", val, proto);
            return send_command(buf);
        } else if (strcmp(target, "proto") == 0) {
            snprintf(buf, sizeof(buf), "block_proto %s", val);
            return send_command(buf);
        } else {
            fprintf(stderr, "%s[ERROR]%s Unknown block target: %s\n", COLOR_RED, COLOR_RESET, target);
            return 1;
        }
    } else if (strcmp(action, "help") == 0 || strcmp(action, "--help") == 0 || strcmp(action, "-h") == 0) {
        print_help(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "%s[ERROR]%s Unknown command '%s'. Run '%s help'\n",
                COLOR_RED, COLOR_RESET, action, argv[0]);
        return 1;
    }

    return 0;
}
