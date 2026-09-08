#ifdef _WIN32
#include <windows.h>
#define API extern "C" __declspec(dllexport) __declspec(noinline)
API int guarded_read(int *value) { __try { return *value; } __except(1) { return -1; } }
volatile int tls_seen;
void NTAPI depth_tls(void*,DWORD reason,void*) { if(reason==DLL_PROCESS_ATTACH)tls_seen=1; }
#pragma section(".CRT$XLB",long,read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK depth_tls_pointer=depth_tls;
#ifdef _WIN64
#pragma comment(linker,"/INCLUDE:_tls_used")
#pragma comment(linker,"/INCLUDE:depth_tls_pointer")
#else
#pragma comment(linker,"/INCLUDE:__tls_used")
#pragma comment(linker,"/INCLUDE:_depth_tls_pointer")
#endif
#else
#define API extern "C" __attribute__((visibility("default"),noinline))
API int guarded_read(int *value){try{if(!value)throw 7;return *value;}catch(int){return -1;}}
#endif
struct Base {virtual int value(){return 7;}};
struct Derived:Base {int value() override {return 42;}};
API int dispatch_value(Base *object){return object->value();}
int (*volatile chosen_dispatch)(Base*)=dispatch_value;
API int dispatch_chosen(Base *object){return chosen_dispatch(object);}
int main(){Derived object;int value=7;return dispatch_value(&object)==42&&guarded_read(&value)==7?0:1;}
