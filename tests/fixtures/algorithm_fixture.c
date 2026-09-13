#include <stdio.h>
/* Independent tiny input/output oracle; no challenge answers or archive data. */
int main(void) { int c;while((c=getchar())!=EOF)putchar((unsigned char)c ^ 0x20);return ferror(stdin)?1:0; }
