#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
int main(int argc, char **argv) {
  if(argc>1&&!strcmp(argv[1],"--solve-input")) {
    char input[8]={0},copied[8]={0};int (*volatile compare)(const void *,const void *,size_t);void *(*volatile copy)(void *,const void *,size_t);
#ifdef _WIN32
    DWORD received=0;if(!ReadFile(GetStdHandle(STD_INPUT_HANDLE),input,sizeof(input),&received,NULL)||received!=sizeof(input))return 10;
    HMODULE crt=LoadLibraryW(L"ucrtbase.dll");if(!crt)return 11;
    compare=(int (*)(const void *,const void *,size_t))GetProcAddress(crt,"memcmp");
    copy=(void *(*)(void *,const void *,size_t))GetProcAddress(crt,"memcpy");
#else
    if(read(0,input,sizeof(input))!=sizeof(input))return 10;
    compare=memcmp;copy=memcpy;
#endif
    if(!compare||!copy)return 12;
    copy(copied,input,sizeof(input));
    if(compare(copied,"Birch42!",sizeof(input))==0) {fputs("PASS",stdout);fflush(stdout);return 0;}
    fputs("FAIL",stdout);return 1;
  }
  if (argc > 1 && !strcmp(argv[1], "--unpack")) {
    /* Harmless return-42 code, reconstructed with subtraction, not XOR. */
    const unsigned char encoded[] = {0xb9, 0x2b, 1, 1, 1, 0xc4};
#ifdef _WIN32
    unsigned char *code =
        VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old;
    if (!code)
      return 7;
#else
    unsigned char *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED)
      return 7;
#endif
    for (unsigned i = 0; i < sizeof(encoded); ++i)
      code[i] = encoded[i] - 1;
#ifdef _WIN32
    if (!VirtualProtect(code, 4096, PAGE_EXECUTE_READ, &old))
      return 8;
    FlushInstructionCache(GetCurrentProcess(), code, 4096);
#else
    if (mprotect(code, 4096, PROT_READ | PROT_EXEC))
      return 8;
#endif
    int result = ((int (*)(void))code)();
    printf("unpacked:%d", result);
#ifdef _WIN32
    VirtualFree(code, 0, MEM_RELEASE);
#else
    munmap(code, 4096);
#endif
    return result == 42 ? 0 : 9;
  }
  if (argc > 1 && !strcmp(argv[1], "--companion")) {
    FILE *ready = fopen("ready", "wb");
    if (!ready)
      return 6;
    fputs("READY", ready);
    fclose(ready);
#ifdef _WIN32
    Sleep(3000);
#else
    usleep(3000000);
#endif
    return 0;
  }
  char input[32] = {0}, payload[32] = {0};
  if (argc < 2 || strcmp(argv[1], "--fixture"))
    return 2;
  if (!fgets(input, sizeof(input), stdin))
    return 3;
  FILE *f = fopen("payload", "rb");
  if (!f)
    return 4;
  fread(payload, 1, sizeof(payload) - 1, f);
  fclose(f);
  const char *env = getenv("EXPERIMENT_VALUE");
  char output[128];
  snprintf(output, sizeof(output), "%s:%s:%s",
           !strcmp(input, "yes\n") ? "accepted" : "rejected",
           env ? env : "missing", payload);
  f = fopen("delivery.txt", "wb");
  if (!f)
    return 5;
  fputs(output, f);
  fclose(f);
  fputs(output, stdout);
  return 0;
}
