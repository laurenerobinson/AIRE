#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int authenticate(const char *password) {
    char secret[] = "aire_demo";
    
    if (strcmp(password, secret) == 0) {
        return 1;
    }
    return 0;
}

void show_secret() {
    printf("Access granted. Hidden feature enabled.\n");
}

void deny_access() {
    printf("Access denied.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    int result = authenticate(argv[1]);

    if (result) {
        show_secret();
    } else {
        deny_access();
    }

    return 0;
}
