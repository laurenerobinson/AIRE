/* Negative control for API-presence rules, not a general proof of program safety. */
#include <stddef.h>
#include <string.h>

__attribute__((noinline))
int copy_input(const char *source)
{
    char destination[16];
    size_t length = strlen(source);
    if (length >= sizeof destination)
        return -1;
    memcpy(destination, source, length + 1);
    return (unsigned char)destination[0];
}

int main(int argc, char **argv)
{
    return argc > 1 ? copy_input(argv[1]) : 0;
}
