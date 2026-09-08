#ifdef _WIN32
#include <windows.h>
void start(void) {
  volatile unsigned char *code=VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  if(!code)ExitProcess(1);
  code[0]=0xb8;code[1]=42;code[2]=0;code[3]=0;code[4]=0;code[5]=0xc3;
  DWORD old;if(!VirtualProtect((void*)code,4096,PAGE_EXECUTE_READ,&old))ExitProcess(2);
  FlushInstructionCache(GetCurrentProcess(),(void*)code,6);
  int value=((int(*)(void))code)();VirtualFree((void*)code,0,MEM_RELEASE);ExitProcess(value==42?0:3);
}
#else
#include <sys/mman.h>
int main(void) {
  volatile unsigned char *code=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(code==MAP_FAILED)return 1;
  code[0]=0xb8;code[1]=42;code[2]=0;code[3]=0;code[4]=0;code[5]=0xc3;
  if(mprotect((void*)code,4096,PROT_READ|PROT_EXEC))return 2;
  int value=((int(*)(void))code)();munmap((void*)code,4096);return value==42?0:3;
}
#endif
