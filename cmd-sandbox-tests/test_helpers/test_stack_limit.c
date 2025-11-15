#include <stdio.h>
#include <string.h>

void use_stack(int depth) {
    // Each call uses ~1MB of stack (array of 250000 ints = ~1MB)
    int large_array[250000];
    memset(large_array, 0, sizeof(large_array));
    large_array[0] = depth;
    
    if (depth < 20) {  // Try to use 20MB total (exceeds 8MB limit)
        use_stack(depth + 1);
    }
}

int main() {
    printf("Attempting to use >8MB stack...\n");
    use_stack(0);
    printf("Stack usage succeeded (should not reach here if limit enforced)\n");
    return 0;
}
