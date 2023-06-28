#include <stdio.h>
#include <pcap.h>

#define FILTER_EXP "port 23"
#define MAX_ERRBUF_SIZE PCAP_ERRBUF_SIZE

void handle_error(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    pcap_perror(handle, message);
    pcap_close(handle);
    exit(1);
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char *dev;
    char errbuf[MAX_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        handle_error("Couldn't find default device");
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
        handle_error("Couldn't open device");
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, FILTER_EXP, 0, net) == -1) {
        handle_error("Couldn't parse filter");
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        handle_error("Couldn't install filter");
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);

    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);

    /* Close the session */
    pcap_close(handle);
    return 0;
}