// Native deployment API wrapper, not a debugger or another instruction decoder.
#include "dr_api.h"
#include "dr_config.h"
#include "dr_inject.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif
static unsigned long long millis(void) {
#ifdef WINDOWS
  return GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}
int main(int argc, char **argv) {
  // root, client, events, result, cancel, max-events, timeout, cwd, config,
  // target, args...
  if (argc < 13)
    return 2;
  unsigned limit = (unsigned)strtoul(argv[6], NULL, 10);
  unsigned timeout = (unsigned)strtoul(argv[7], NULL, 10);
  if (!limit || limit > 10000 || !timeout || timeout > 60000)
    return 2;
  FILE *result = fopen(argv[4], "wb");
  if (!result)
    return 2;
#ifdef WINDOWS
  if (!SetEnvironmentVariableA("DYNAMORIO_CONFIGDIR", argv[9]) ||
      !SetCurrentDirectoryA(argv[8]))
    return 2;
#else
  if (setenv("DYNAMORIO_CONFIGDIR", argv[9], 1) || chdir(argv[8]))
    return 2;
#endif
  void *data = NULL;
  int error =
      dr_inject_process_create(argv[12], (const char **)&argv[12], &data);
  bool registered = false, ran = false, done = false, cancelled = false;
  const char *name = data ? dr_inject_get_image_name(data) : "";
  process_id_t pid = data ? dr_inject_get_process_id(data) : 0;
  char options[4096];
  if (!error) {
    error = dr_register_process(name, pid, false, argv[1],
                                DR_MODE_CODE_MANIPULATION, false,
                                DR_PLATFORM_DEFAULT, "-no_follow_children");
    registered = error == DR_SUCCESS;
  }
  if (!error) {
    for (const char *p = argv[3]; *p; ++p)
      if (*p == '"' || *p == ';' || *p == '\n' || *p == '\r')
        error = -2;
    if (!error) {
      int n = snprintf(options, sizeof(options), "\"%s\" %u %s %s", argv[3], limit,argv[10],argv[11]);
      if (n < 0 || n >= sizeof(options))
        error = -2;
      else
        error = dr_register_client(name, pid, false, DR_PLATFORM_DEFAULT, 0, 0,
                                   argv[2], options);
    }
  }
  if (!error && !dr_inject_process_inject(data, false, NULL))
    error = -3;
  if (!error) {
    ran = dr_inject_process_run(data);
    if (!ran)
      error = -4;
  }
  unsigned long long start = millis();
  while (ran && millis() - start < timeout) {
    FILE *cancel = fopen(argv[5], "rb");
    if (cancel) {
      fclose(cancel);
      cancelled = true;
      break;
    }
    if (dr_inject_wait_for_child(data, 25)) {
      done = true;
      break;
    }
  }
  // A bounded instrument run authorizes terminating its explicitly launched
  // target.
  if (registered)
    dr_unregister_process(name, pid, false, DR_PLATFORM_DEFAULT);
  int code = data ? dr_inject_process_exit(data, !done) : -1;
  fprintf(result,
          "{\"backend\":\"dynamorio\",\"pid\":%u,\"native_error\":%d,\"exit_"
          "code\":%d,\"timed_out\":%s,\"cancelled\":%s}\n",
          (unsigned)pid, error, code,
          ran && !done && !cancelled ? "true" : "false",
          cancelled ? "true" : "false");
  fclose(result);
  return error ? 1 : 0;
}
