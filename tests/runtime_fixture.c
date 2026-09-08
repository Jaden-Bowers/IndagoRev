#include <string.h>
#include <stdio.h>
#if defined(_WIN32)
#include <windows.h>
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#else
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#define EXPORT __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
#endif
EXPORT volatile unsigned runtime_input = 7;
EXPORT volatile unsigned runtime_output = 0;
EXPORT NOINLINE unsigned runtime_probe(unsigned input) {
  if (input == 7)
    runtime_output = 42;
  else
    runtime_output = input + 3;
  return runtime_output;
}
int main(int argc, char **argv) {
  if(argc>1&&!strcmp(argv[1],"children")) {
#if defined(_WIN32)
    char path[32768],command[32780];GetModuleFileNameA(NULL,path,sizeof(path));
    snprintf(command,sizeof(command),"\"%s\" child",path);STARTUPINFOA startup={sizeof(startup)};PROCESS_INFORMATION process={0};
    if(!CreateProcessA(path,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&process))return 4;
    WaitForSingleObject(process.hProcess,10000);CloseHandle(process.hThread);CloseHandle(process.hProcess);
#else
    pid_t child=fork();if(child<0)return 4;if(!child){execl(argv[0],argv[0],"child",NULL);_exit(5);}waitpid(child,NULL,0);
#endif
    return 0;
  }
  if(argc>1&&!strcmp(argv[1],"child")){runtime_probe(7);return 0;}
  (void)argv;
  if (argc > 1) {
#if defined(_WIN32)
    Sleep(10000);
#else
    // Opt in only in this harmless attach fixture; never change host policy.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    sleep(10);
#endif
  }
  runtime_probe(runtime_input);
  return 0;
}
