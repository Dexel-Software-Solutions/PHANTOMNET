/*
 * PHANTOMNET — Protocol Deception Engine
 * ARP and DNS spoofing at the raw socket level.
 * Injects fake host responses for attacker-facing deception topology.
 *
 * Author: Demiyan Dissanayake | Dexel Software Solutions
 * License: MIT
 *
 * Build: gcc -O2 -Wall -o spoofer spoofer.c -lpcap
 * Run:   sudo ./spoofer --iface eth0 --socket /tmp/phantomnet_spoof.sock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pcap/pcap.h>

/* ─── Constants ──────────────────────────────────────────── */
#define ARP_REQUEST         1
#define ARP_REPLY           2
#define ETH_ARP             0x0806
#define ETH_IP              0x0800
#define DNS_PORT            53
#define MAX_FAKE_HOSTS      512
#define CMD_BUFFER_SIZE     2048
#define IFACE_MAX           64
#define IP_STR_MAX          16
#define MAC_STR_MAX         18

/* ─── Structures ─────────────────────────────────────────── */

/* Ethernet + ARP combined frame for raw sending */
struct arp_packet {
    /* Ethernet header */
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;
    /* ARP header */
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_size;
    uint8_t  proto_size;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} __attribute__((packed));

/* Fake host entry loaded from Python orchestrator via IPC */
struct fake_host {
    char     ip[IP_STR_MAX];
    uint8_t  mac[6];
    char     hostname[128];
    int      active;
};

/* ─── Globals ────────────────────────────────────────────── */
static volatile int running = 1;
static struct fake_host fake_hosts[MAX_FAKE_HOSTS];
static int fake_host_count = 0;
static char iface_name[IFACE_MAX] = "eth0";
static uint8_t real_iface_mac[6];
static int raw_sock = -1;
static int ipc_sock = -1;

/* ─── Signal handler ─────────────────────────────────────── */
static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

/* ─── Utility: parse MAC from "AA:BB:CC:DD:EE:FF" string ─── */
static int parse_mac(const char *mac_str, uint8_t *out) {
    unsigned int v[6];
    if (sscanf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

/* ─── Get interface MAC address ──────────────────────────── */
static int get_iface_mac(const char *iface, uint8_t *mac_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

/* ─── Send ARP reply spoofing a fake host ─────────────────── */
static void send_arp_reply(
    const uint8_t *target_mac,
    uint32_t       target_ip,
    const uint8_t *fake_mac,
    uint32_t       fake_ip
) {
    struct arp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* Ethernet header */
    memcpy(pkt.dst_mac, target_mac, 6);
    memcpy(pkt.src_mac, fake_mac, 6);
    pkt.eth_type = htons(ETH_ARP);

    /* ARP body */
    pkt.hw_type    = htons(1);          /* Ethernet */
    pkt.proto_type = htons(ETH_IP);
    pkt.hw_size    = 6;
    pkt.proto_size = 4;
    pkt.opcode     = htons(ARP_REPLY);

    memcpy(pkt.sender_mac, fake_mac, 6);
    pkt.sender_ip = fake_ip;

    memcpy(pkt.target_mac, target_mac, 6);
    pkt.target_ip = target_ip;

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = if_nametoindex(iface_name);
    sa.sll_halen    = 6;
    memcpy(sa.sll_addr, target_mac, 6);

    ssize_t sent = sendto(
        raw_sock, &pkt, sizeof(pkt), 0,
        (struct sockaddr *)&sa, sizeof(sa)
    );
    if (sent < 0) {
        perror("[Spoofer] sendto ARP failed");
    }
}

/* ─── Process ARP request from pcap ─────────────────────── */
static void process_arp_packet(const u_char *data, int len) {
    if (len < (int)(sizeof(struct arp_packet))) return;

    const struct arp_packet *arp = (const struct arp_packet *)data;
    if (ntohs(arp->eth_type) != ETH_ARP) return;
    if (ntohs(arp->opcode) != ARP_REQUEST) return;

    uint32_t requested_ip = arp->target_ip;
    char requested_ip_str[IP_STR_MAX];
    struct in_addr addr;
    addr.s_addr = requested_ip;
    strncpy(requested_ip_str, inet_ntoa(addr), IP_STR_MAX - 1);

    /* Check if requested IP matches a fake host */
    for (int i = 0; i < fake_host_count; i++) {
        if (!fake_hosts[i].active) continue;
        if (strcmp(fake_hosts[i].ip, requested_ip_str) == 0) {
            printf("[Spoofer] ARP spoof: %s -> %02X:%02X:%02X:%02X:%02X:%02X\n",
                   requested_ip_str,
                   fake_hosts[i].mac[0], fake_hosts[i].mac[1],
                   fake_hosts[i].mac[2], fake_hosts[i].mac[3],
                   fake_hosts[i].mac[4], fake_hosts[i].mac[5]);
            send_arp_reply(
                arp->sender_mac,
                arp->sender_ip,
                fake_hosts[i].mac,
                requested_ip
            );
            return;
        }
    }
}

/* ─── IPC: load fake host JSON line from Python ─────────── */
/*
 * Expected format (newline-delimited JSON per host):
 * {"ip":"10.10.20.2","mac":"00:0C:29:AA:BB:CC","hostname":"web-01.corp.local"}
 */
static void load_fake_host_from_json(const char *json_line) {
    if (fake_host_count >= MAX_FAKE_HOSTS) {
        fprintf(stderr, "[Spoofer] Max fake hosts reached (%d)\n", MAX_FAKE_HOSTS);
        return;
    }
    struct fake_host *h = &fake_hosts[fake_host_count];
    memset(h, 0, sizeof(*h));

    /* Simple JSON field extraction (no external lib dependency) */
    const char *ip_start = strstr(json_line, "\"ip\":\"");
    const char *mac_start = strstr(json_line, "\"mac\":\"");
    const char *hn_start = strstr(json_line, "\"hostname\":\"");

    if (!ip_start || !mac_start) return;

    /* Extract IP */
    ip_start += 6;
    char ip_buf[IP_STR_MAX] = {0};
    int j = 0;
    while (*ip_start && *ip_start != '"' && j < IP_STR_MAX - 1)
        ip_buf[j++] = *ip_start++;
    strncpy(h->ip, ip_buf, IP_STR_MAX - 1);

    /* Extract MAC */
    mac_start += 7;
    char mac_buf[MAC_STR_MAX] = {0};
    j = 0;
    while (*mac_start && *mac_start != '"' && j < MAC_STR_MAX - 1)
        mac_buf[j++] = *mac_start++;
    if (parse_mac(mac_buf, h->mac) != 0) return;

    /* Extract hostname (optional) */
    if (hn_start) {
        hn_start += 12;
        j = 0;
        while (*hn_start && *hn_start != '"' && j < 127)
            h->hostname[j++] = *hn_start++;
    }

    h->active = 1;
    fake_host_count++;
    printf("[Spoofer] Loaded fake host: %s (%s)\n", h->ip, h->hostname);
}

/* ─── IPC reader: receive commands from Python via socket ── */
static void process_ipc(int sock_fd) {
    char buf[CMD_BUFFER_SIZE];
    ssize_t n = recv(sock_fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
    if (n <= 0) return;
    buf[n] = '\0';

    /* Handle CLEAR command */
    if (strncmp(buf, "CLEAR", 5) == 0) {
        fake_host_count = 0;
        memset(fake_hosts, 0, sizeof(fake_hosts));
        printf("[Spoofer] Fake host table cleared.\n");
        return;
    }

    /* Process newline-delimited host entries */
    char *line = strtok(buf, "\n");
    while (line) {
        if (line[0] == '{') {
            load_fake_host_from_json(line);
        }
        line = strtok(NULL, "\n");
    }
}

/* ─── pcap packet handler callback ──────────────────────── */
static void pcap_handler(
    u_char *user,
    const struct pcap_pkthdr *header,
    const u_char *data
) {
    (void)user;
    process_arp_packet(data, (int)header->caplen);
}

/* ─── Main ───────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    char ipc_socket_path[256] = "/tmp/phantomnet_spoof.sock";
    char pcap_err[PCAP_ERRBUF_SIZE];

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc)
            strncpy(iface_name, argv[++i], IFACE_MAX - 1);
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            strncpy(ipc_socket_path, argv[++i], 255);
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[Spoofer] Interface: %s\n", iface_name);
    printf("[Spoofer] IPC socket: %s\n", ipc_socket_path);

    /* Get interface MAC */
    if (get_iface_mac(iface_name, real_iface_mac) != 0) {
        fprintf(stderr, "[Spoofer] Failed to get MAC for %s\n", iface_name);
        return 1;
    }
    printf("[Spoofer] Interface MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           real_iface_mac[0], real_iface_mac[1], real_iface_mac[2],
           real_iface_mac[3], real_iface_mac[4], real_iface_mac[5]);

    /* Open raw socket for sending ARP replies */
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("[Spoofer] raw socket");
        return 1;
    }

    /* Bind raw socket to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(iface_name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[Spoofer] bind raw socket");
        close(raw_sock);
        return 1;
    }

    /* Open Unix IPC socket to receive fake host table from Python */
    ipc_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc_sock < 0) {
        perror("[Spoofer] IPC socket create");
        close(raw_sock);
        return 1;
    }
    struct sockaddr_un un_addr;
    memset(&un_addr, 0, sizeof(un_addr));
    un_addr.sun_family = AF_UNIX;
    strncpy(un_addr.sun_path, ipc_socket_path, sizeof(un_addr.sun_path) - 1);
    unlink(ipc_socket_path);
    if (bind(ipc_sock, (struct sockaddr *)&un_addr, sizeof(un_addr)) < 0) {
        perror("[Spoofer] IPC socket bind");
        close(raw_sock);
        close(ipc_sock);
        return 1;
    }
    listen(ipc_sock, 1);

    /* Open pcap for capturing ARP requests */
    pcap_t *handle = pcap_open_live(iface_name, 65535, 1, 100, pcap_err);
    if (!handle) {
        fprintf(stderr, "[Spoofer] pcap_open_live: %s\n", pcap_err);
        close(raw_sock);
        close(ipc_sock);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
    pcap_setnonblock(handle, 1, pcap_err);

    printf("[Spoofer] Ready. Listening for ARP requests...\n");

    /* Accept IPC connection from Python */
    int client_fd = -1;
    fd_set fds;
    struct timeval tv;

    while (running) {
        FD_ZERO(&fds);
        FD_SET(ipc_sock, &fds);
        if (client_fd >= 0) FD_SET(client_fd, &fds);
        int maxfd = (client_fd > ipc_sock) ? client_fd : ipc_sock;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; /* 100ms */

        int sel = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (sel > 0) {
            if (FD_ISSET(ipc_sock, &fds)) {
                client_fd = accept(ipc_sock, NULL, NULL);
                printf("[Spoofer] Python core connected via IPC.\n");
            }
            if (client_fd >= 0 && FD_ISSET(client_fd, &fds)) {
                process_ipc(client_fd);
            }
        }

        /* Process ARP packets */
        pcap_dispatch(handle, 10, pcap_handler, NULL);
    }

    printf("[Spoofer] Shutting down.\n");
    pcap_close(handle);
    if (client_fd >= 0) close(client_fd);
    close(ipc_sock);
    close(raw_sock);
    unlink(ipc_socket_path);
    return 0;
}
