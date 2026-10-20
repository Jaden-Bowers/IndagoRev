// Source-backed ARM fixture: analyzed as bytes, never launched by IndagoRev.
#include <stddef.h>
__attribute__((noinline)) void decode_buffer(unsigned char* data, size_t count) {
  for (size_t i = 0; i < count; ++i) data[i] ^= 0x5a;
}
__attribute__((noinline)) int check_result(const unsigned char* data) {
  return data[0] == 'H';
}
int main(void) {
  unsigned char data[] = {0x12, 0x3f, 0x36, 0x36, 0x35, 0};
  decode_buffer(data, 5);
  return check_result(data) ? 0 : 1;
}
