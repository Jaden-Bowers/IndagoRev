#include <stdio.h>
extern const unsigned char fixture_payload_begin[], fixture_payload_end[];
int main(void) {
    const size_t count = (size_t)(fixture_payload_end - fixture_payload_begin);
    return fwrite(fixture_payload_begin, 1, count, stdout) == count ? 0 : 1;
}
