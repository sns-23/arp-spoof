#ifndef __ATTACK_H__
#define __ATTACK_H__ 

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct attack_ctx {
    pcap_t *handle;
    char interface[IFNAMSIZ];
    Ip my_ip;
    Mac my_mac;
    struct info *infoes;
    int info_count;
};

struct info {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

int get_st_info(struct attack_ctx *ctx);
int get_my_info(struct attack_ctx *ctx);
int spoof_packet(struct attack_ctx *ctx);
#endif /* __ATTACK_H__ */