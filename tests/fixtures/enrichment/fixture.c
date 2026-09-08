#include <stdio.h>
#include <stddef.h>
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
/* Compile-only reverse-engineering fixture; no networking or filesystem effects. */
static unsigned char encoded[] = {
    0x13,0x34,0x3e,0x3b,0x3d,0x35,0x7a,0x35,0x3c,0x3c,
    0x36,0x33,0x34,0x3f,0x7a,0x3e,0x3f,0x39,0x35,0x3e,
    0x3f,0x3e,0x7a,0x37,0x3b,0x28,0x31,0x3f,0x28
};
NOINLINE void decode_marker(char *output, const unsigned char *input, size_t count, unsigned char key) {
    size_t index;
    for(index=0;index<count;++index) output[index]=(char)(input[index]^key);
    output[count]=0;
}
int main(void) {
    char output[64];
    decode_marker(output,encoded,sizeof(encoded),0x5a);
    puts(output);
    return 0;
}
