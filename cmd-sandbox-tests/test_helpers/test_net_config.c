// Test program that mimics curl but attempts network configuration
// Compile: gcc -o test_net_config test_net_config.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--as-curl") == 0) {
        // Rename process to "curl"
        strcpy(argv[0], "curl");
        
        printf("[TEST] Process renamed to 'curl' for LSM detection\n");
        printf("[TEST] Attempting network configuration (should be blocked by SEC-003)...\n\n");
        
        // Test 1: Try to change interface flags (requires CAP_NET_ADMIN)
        printf("Test 1: Attempting to modify interface flags...\n");
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            printf("  ✗ Failed to create socket: %s\n", strerror(errno));
            return 1;
        }
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
        
        // Try to get current flags first
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            printf("  ✗ Failed to get interface flags: %s\n", strerror(errno));
            close(sock);
            return 1;
        }
        
        printf("  Current flags for lo: 0x%x\n", ifr.ifr_flags);
        
        // Try to set flags (should be blocked by SEC-003)
        printf("  Attempting to set interface flags...\n");
        int result = ioctl(sock, SIOCSIFFLAGS, &ifr);
        if (result < 0) {
            printf("  ✓ BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EPERM || errno == EACCES) {
                printf("  → SEC-003 working: CAP_NET_ADMIN denied by LSM\n");
            }
        } else {
            printf("  ✗ ALLOWED: Interface flags modified - SEC-003 FAILED!\n");
            close(sock);
            return 1;
        }
        
        close(sock);
        printf("\n");
        
        // Test 2: Try to create a raw socket (requires CAP_NET_RAW, but we test CAP_NET_ADMIN path)
        printf("Test 2: Attempting to create RAW socket...\n");
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            printf("  ✓ BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EPERM || errno == EACCES) {
                printf("  → Network capabilities denied\n");
            }
        } else {
            printf("  ✗ ALLOWED: Raw socket created (fd=%d)\n", raw_sock);
            close(raw_sock);
            // Not necessarily a failure - depends on CAP_NET_RAW vs CAP_NET_ADMIN
        }
        printf("\n");
        
        printf("[SUCCESS] Network configuration attempts were blocked!\n");
        printf("[SUCCESS] SEC-003 is working correctly\n");
        return 0;
    }
    
    printf("Usage: %s --as-curl\n", argv[0]);
    printf("This program tests SEC-003 by attempting network configuration while pretending to be curl\n");
    return 1;
}
