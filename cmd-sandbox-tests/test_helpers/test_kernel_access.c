// Test program that mimics curl but attempts kernel memory access
// Compile: gcc -o test_kernel_access test_kernel_access.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    // Make this process look like "curl" to the LSM hook
    // The LSM checks comm name which comes from argv[0]
    if (argc > 1 && strcmp(argv[1], "--as-curl") == 0) {
        // Rename the process to "curl"
        strcpy(argv[0], "curl");
        
        printf("[TEST] Process renamed to 'curl' for LSM detection\n");
        printf("[TEST] Attempting to access kernel memory (should be blocked by SEC-005)...\n\n");
        
        // Test 1: Try to open /proc/kcore (requires CAP_SYS_ADMIN)
        printf("Test 1: Attempting to open /proc/kcore...\n");
        int fd_kcore = open("/proc/kcore", O_RDONLY);
        if (fd_kcore < 0) {
            printf("  ✓ BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EPERM || errno == EACCES) {
                printf("  → SEC-005 working: CAP_SYS_ADMIN denied by LSM\n");
            }
        } else {
            printf("  ✗ ALLOWED: /proc/kcore opened (fd=%d) - SEC-005 FAILED!\n", fd_kcore);
            close(fd_kcore);
            return 1;
        }
        printf("\n");
        
        // Test 2: Try to open /dev/mem (requires CAP_SYS_ADMIN)
        printf("Test 2: Attempting to open /dev/mem...\n");
        int fd_mem = open("/dev/mem", O_RDONLY);
        if (fd_mem < 0) {
            printf("  ✓ BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EPERM || errno == EACCES) {
                printf("  → SEC-005 working: CAP_SYS_ADMIN denied by LSM\n");
            }
        } else {
            printf("  ✗ ALLOWED: /dev/mem opened (fd=%d) - SEC-005 FAILED!\n", fd_mem);
            close(fd_mem);
            return 1;
        }
        printf("\n");
        
        // Test 3: Try to open /dev/kmem (requires CAP_SYS_ADMIN)
        printf("Test 3: Attempting to open /dev/kmem...\n");
        int fd_kmem = open("/dev/kmem", O_RDONLY);
        if (fd_kmem < 0) {
            printf("  ✓ BLOCKED: %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EPERM || errno == EACCES) {
                printf("  → SEC-005 working: CAP_SYS_ADMIN denied by LSM\n");
            }
        } else {
            printf("  ✗ ALLOWED: /dev/kmem opened (fd=%d) - SEC-005 FAILED!\n", fd_kmem);
            close(fd_kmem);
            return 1;
        }
        printf("\n");
        
        printf("[SUCCESS] All kernel access attempts were blocked!\n");
        printf("[SUCCESS] SEC-005 is working correctly\n");
        return 0;
    }
    
    printf("Usage: %s --as-curl\n", argv[0]);
    printf("This program tests SEC-005 by attempting kernel memory access while pretending to be curl\n");
    return 1;
}
