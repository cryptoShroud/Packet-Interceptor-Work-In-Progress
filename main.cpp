#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <oneapi/tbb/cache_aligned_allocator.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define PROXY_PORT 8080
#define BUFFER_SIZE 4096

// void process_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
//     printf("intercepted packet, first 16 bytes:");
//     for (int i = 0;i < header->len; i++) {
//         printf("%02x ", packet[i]);
//     }
//     printf("\n");
// }
void process_packet(u_char *user_data,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    const struct ether_header *eth =
        (struct ether_header*)packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    const struct ip *ip_hdr =
        (struct ip*)(packet + sizeof(struct ether_header));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));

    printf("\nPacket captured\n");
    printf("   IP  %s -> %s\n", src_ip, dst_ip);
    printf("   Protocol: ");


    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp =
            (struct tcphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));

        printf("TCP\n");
        printf("   Ports: %u → %u\n",
               ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));
    }

    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp =
            (struct udphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));

        printf("UDP\n");
        printf("   Ports: %u → %u\n",
               ntohs(udp->uh_sport),
               ntohs(udp->uh_dport));
    }
    else {
        printf("Other (%d)\n", ip_hdr->ip_p);
    }

    printf("   Length: %u bytes\n", header->len);
}


void *handle_connection(void *client_socket) {
    int client_fd  = *(int*)client_socket;
    free(client_socket);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("SSL_CTX_new failed");
        close(client_fd);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, "midm_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "midm_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        SSL_CTX_free(ctx);
        return NULL;
        }


    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;   

        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(443);
        inet_pton(AF_INET, "180.95.39.178", &target_addr.sin_addr);

        if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            perror("Connect to target failed");
            close(client_fd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return NULL;
        }

        SSL_CTX *target_ctx = SSL_CTX_new(TLS_client_method());
        SSL *target_ssl = SSL_new(target_ctx);
        SSL_set_fd(target_ssl, target_fd);

        if (SSL_connect(target_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(target_fd);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return NULL;
        }

        char buffer[BUFFER_SIZE];
        while (true) {
            int read_len = SSL_read(ssl, buffer, sizeof(buffer));
            if (read_len > 0) {
                SSL_write(target_ssl, buffer, read_len);

                int response_len = SSL_read(target_ssl, buffer, sizeof(buffer));
                if (response_len > 0) {
                    SSL_write(ssl, buffer, response_len);
                }
            } else if (read_len == 0) {
                break;
            } else {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        SSL_shutdown(target_ssl);
        SSL_free(target_ssl);
        SSL_CTX_free(target_ctx);
        close(client_fd);
        close(target_fd);
        return NULL;
    }
}

    void* pcap_thread(void*) {
        char errbuf[PCAP_ERRBUF_SIZE];
        char *dev = pcap_lookupdev(errbuf);

        if (!dev) {
            fprintf(stderr, "pcap_lookupdev failed: %s\n", errbuf);
            return NULL;
        }

        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
            return NULL;
        }

        pcap_loop(handle, -1, process_packet, NULL);
        pcap_close(handle);
        return NULL;
    }

    int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PROXY_PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 10);

    pthread_t pcap_tid;
    pthread_create(&pcap_tid, NULL, pcap_thread, NULL);
    pthread_detach(pcap_tid);

    while (1) {
        int client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        int *pclient = (int*)malloc(sizeof(int));
        *pclient = client_fd;

        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_connection, pclient);
        pthread_detach(thread_id);

    }

    close(server_fd);
    return 0;
}
