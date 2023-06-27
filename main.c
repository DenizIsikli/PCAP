#include <stdio.h>
#include <pcap.h>

#define FILTER_EXP "port 23"
#define MAX_ERRBUF_SIZE PCAP_ERRBUF_SIZE

int main(int argc, char *argv[]) {
    pcap_t *handle;                   /* Session handle */
    char *dev;                        /* The device to sniff on */
    char errbuf[MAX_ERRBUF_SIZE];      /* Error string */
    struct bpf_program fp;             /* The compiled filter */
    bpf_u_int32 mask;                  /* Our netmask */
    bpf_u_int32 net;                   /* Our IP */
    struct pcap_pkthdr header;         /* The header that pcap gives us */
    const u_char *packet;              /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fputs("Couldn't find default device\n", stderr);
        return 2;
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, FILTER_EXP, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        return 2;
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);

    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);

    /* Close the session */
    pcap_close(handle);
    return 0;
}