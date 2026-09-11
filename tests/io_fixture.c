/* Benign bounded native process for receipt diagnostics, not a benchmark solve. */
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#endif
int main(int argc,char **argv) {
#ifdef _WIN32
  _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
  if(argc>1&&!strcmp(argv[1],"sleep")) {
#ifdef _WIN32
    Sleep(2000);
#else
    sleep(2);
#endif
    return 0;
  }
  if(argc>1&&!strcmp(argv[1],"flood")){for(int i=0;i<2000;++i)putchar('x');return 0;}
  if(argc>1&&!strcmp(argv[1],"binary")){putchar(255);return 0;}
  if(argc>1&&!strcmp(argv[1],"child")) {
#ifdef _WIN32
    char exe[32768],command[32790];GetModuleFileNameA(NULL,exe,sizeof(exe));
    snprintf(command,sizeof(command),"\"%s\" sleep",exe);
    STARTUPINFOA start={0};PROCESS_INFORMATION process={0};start.cb=sizeof(start);start.dwFlags=STARTF_USESTDHANDLES;
    start.hStdInput=GetStdHandle(STD_INPUT_HANDLE);start.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);start.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    if(!CreateProcessA(exe,command,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&start,&process))return 2;
    CloseHandle(process.hThread);CloseHandle(process.hProcess);
#else
    const pid_t child=fork();if(child<0)return 2;if(child==0){sleep(2);_exit(0);}
#endif
    fwrite("OK",1,2,stdout);return 0;
  }
  char input[32];size_t n=fread(input,1,sizeof(input),stdin);
  if((argc>1&&!strcmp(argv[1],"ignore"))||(n==4&&!memcmp(input,"OPEN",4))){fwrite("OK",1,2,stdout);return 0;}
  fwrite("NO",1,2,stdout);return 1;
}
