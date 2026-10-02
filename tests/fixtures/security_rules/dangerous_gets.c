/* Static-analysis fixture only. gets is intentionally declared for linkage
 * on local libc versions retaining its compatibility symbol. Never execute. */
extern char *gets(char *);

__attribute__((noinline))
int read_input(void)
{
    char destination[16];
    return gets(destination) != 0;
}

int main(void)
{
    return read_input();
}
