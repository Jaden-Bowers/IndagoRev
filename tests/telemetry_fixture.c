#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#endif
int main(void) {
#ifdef _WIN32
  wchar_t environment[8];GetEnvironmentVariableW(L"TEMP",environment,8);
  /* Late-load networking; create/close unconnected sockets and make one invalid
     connect call. No packets, listening ports or remote destinations. */
  HMODULE network=LoadLibraryA("ws2_32.dll");
  if(network){
    typedef int (WINAPI *connect_fn)(UINT_PTR,const void*,int);
    typedef int (WINAPI *startup_fn)(WORD,LPWSADATA);
    typedef SOCKET (WINAPI *socket_fn)(int,int,int);
    typedef int (WINAPI *close_fn)(SOCKET);
    typedef int (WINAPI *cleanup_fn)(void);
    connect_fn connect_api=(connect_fn)GetProcAddress(network,"connect");
    startup_fn startup_api=(startup_fn)GetProcAddress(network,"WSAStartup");
    socket_fn socket_api=(socket_fn)GetProcAddress(network,"socket");
    close_fn close_api=(close_fn)GetProcAddress(network,"closesocket");
    cleanup_fn cleanup_api=(cleanup_fn)GetProcAddress(network,"WSACleanup");
    WSADATA data;
    if(startup_api&&socket_api&&close_api&&cleanup_api&&startup_api(MAKEWORD(2,2),&data)==0){
      for(int i=0;i<2;i++){SOCKET s=socket_api(AF_INET,SOCK_STREAM,0);if(s==INVALID_SOCKET)return 4;close_api(s);}
      cleanup_api();
    }
    if(connect_api)connect_api((UINT_PTR)-1,NULL,0);
    FreeLibrary(network);
  }
  HANDLE sink = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  DWORD written;
  if (sink != INVALID_HANDLE_VALUE) { WriteFile(sink, "telemetry", 9, &written, NULL); CloseHandle(sink); }
#else
  (void)getenv("PATH");
  for(int i=0;i<2;i++){int s=socket(AF_INET,SOCK_STREAM,0);if(s<0)return 4;close(s);}
  (void)connect(-1,NULL,0);
  int sink = open("/dev/null", O_WRONLY);
  if (sink >= 0) { write(sink, "telemetry", 9); close(sink); }
#endif
  /* Benign generated function: return 42. Never download or execute a sample.
   */
  const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
#ifdef _WIN32
  void *p = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!p)
    return 1;
  memcpy(p, code, sizeof(code));
  DWORD old;
  if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old))
    return 2;
  FlushInstructionCache(GetCurrentProcess(), p, 4096);
#else
  void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    return 1;
  memcpy(p, code, sizeof(code));
  if (mprotect(p, 4096, PROT_READ | PROT_EXEC))
    return 2;
#endif
  int answer = ((int (*)(void))p)();
  puts("benign telemetry fixture");
#ifdef _WIN32
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munmap(p, 4096);
#endif
  return answer == 42 ? 0 : 3;
}
