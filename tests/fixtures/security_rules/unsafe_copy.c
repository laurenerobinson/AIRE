/* Static-analysis fixture only. Never execute this intentionally unsafe program. */
#include <string.h>

__attribute__((noinline))
int copy_input(const char *source)
{
    char destination[16];
    strcpy(destination, source);
    return (unsigned char)destination[0];
}

int main(int argc, char **argv)
{
    return argc > 1 ? copy_input(argv[1]) : 0;
}
