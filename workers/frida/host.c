#include "frida-core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recipes.h"

static FILE *events;
static guint count, budget;
static gsize bytes_written;
static gboolean capped, detached, script_error, crashed;
static gint reason;
static void message(FridaScript *script, const gchar *text, GBytes *data,
                    gpointer user) {
  gsize n = strlen(text);
  if (count >= budget + 4 || n > 16384 || bytes_written + n > 4 * 1024 * 1024) {
    capped = TRUE;
    return;
  }
  /* Preserve the original Frida envelope; parse/normalize in the platform. */
  if (strstr(text, "\"type\":\"error\""))
    script_error = TRUE;
  fprintf(events, "%s\n", text);
  fflush(events);
  ++count;
  bytes_written += n + 1;
}
static void on_detached(FridaSession *session, FridaSessionDetachReason why,
                        FridaCrash *crash, gpointer user) {
  reason = why;
  detached = TRUE;
  /* Native text is retained in the parent's bounded host-output field. */
  if (crash) {
    crashed = TRUE;
    const char *summary = frida_crash_get_summary(crash);
    fprintf(stderr, "Frida crash: %.2048s\n", summary ? summary : "unknown");
  }
}
int main(int argc, char **argv) {
  /* events result cancel budget timeout cwd recipe target [args...] */
  if (argc < 9)
    return 2;
  budget = (guint)strtoul(argv[4], NULL, 10);
  guint timeout = (guint)strtoul(argv[5], NULL, 10);
  if (!budget || budget > 10000 || !timeout || timeout > 60000 ||
      (strcmp(argv[7], "io") && strcmp(argv[7], "code") &&
       strcmp(argv[7], "modules") && strcmp(argv[7], "network") && strcmp(argv[7], "config")))
    return 2;
  events = fopen(argv[1], "wbx");
  if (!events)
    return 2;
  frida_init();
  GError *error = NULL;
  FridaDeviceManager *manager = frida_device_manager_new();
  FridaDevice *device = frida_device_manager_get_device_by_type_sync(
      manager, FRIDA_DEVICE_TYPE_LOCAL, 5000, NULL, &error);
  FridaSession *session = NULL;
  FridaScript *script = NULL;
  guint pid = 0;
  gboolean attached = strncmp(argv[8],"pid:",4)==0;
  gboolean cancelled = FALSE, timed_out = FALSE;
  if (!device)
    goto done;
  if(attached)pid=(guint)strtoul(argv[8]+4,NULL,10);
  else {
  FridaSpawnOptions *spawn = frida_spawn_options_new();
  frida_spawn_options_set_cwd(spawn, argv[6]);
  frida_spawn_options_set_argv(spawn, argv + 8, argc - 8);
  frida_spawn_options_set_stdio(spawn, FRIDA_STDIO_PIPE);
  pid = frida_device_spawn_sync(device, argv[8], spawn, NULL, &error);
  g_object_unref(spawn);
  }
  if (!pid)
    goto done;
  session = frida_device_attach_sync(device, pid, NULL, NULL, &error);
  if (!session)
    goto done;
  g_signal_connect(session, "detached", G_CALLBACK(on_detached), NULL);
  char *source = g_strdup_printf("const recipe='%s', budget=%u;\n%s", argv[7],
                                 budget, recipe_source);
  FridaScriptOptions *options = frida_script_options_new();
  frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);
  script =
      frida_session_create_script_sync(session, source, options, NULL, &error);
  g_free(source);
  g_object_unref(options);
  if (!script)
    goto done;
  g_signal_connect(script, "message", G_CALLBACK(message), NULL);
  frida_script_load_sync(script, NULL, &error);
  if (error)
    goto done;
  if(!attached)frida_device_resume_sync(device, pid, NULL, &error);
  if (error)
    goto done;
  gint64 end = g_get_monotonic_time() + (gint64)timeout * 1000;
  while (!detached && !script_error) {
    while (g_main_context_iteration(NULL, FALSE)) {
    }
    FILE *marker = fopen(argv[3], "rb");
    if (marker) {
      fclose(marker);
      cancelled = TRUE;
      break;
    }
    if (g_get_monotonic_time() >= end) {
      timed_out = TRUE;
      break;
    }
    g_usleep(10000);
  }
done:
  /* Only explicitly spawned targets are killed. Never detach a suspended
   * orphan. */
  if (pid && device && !detached && !attached)
    frida_device_kill_sync(device, pid, NULL, NULL);
  if (attached && session && !detached)
    frida_session_detach_sync(session,NULL,NULL);
  for (int i = 0; i < 20; ++i) {
    while (g_main_context_iteration(NULL, FALSE)) {
    }
    g_usleep(1000);
  }
  if (error)
    fprintf(stderr, "Frida: %.4096s\n", error->message);
  FILE *result = fopen(argv[2], "wbx");
  if (result) {
    fprintf(
        result,
        "{\"pid\":%u,\"native_error\":%d,\"detach_reason\":%d,\"events\":%u,"
        "\"timed_out\":%s,\"cancelled\":%s,\"partial\":%s,\"crashed\":%s}\n",
        pid,
        error          ? error->code
        : script_error ? -1
                       : 0,
        reason, count, timed_out ? "true" : "false",
        cancelled ? "true" : "false", capped || crashed ? "true" : "false",
        crashed ? "true" : "false");
    fclose(result);
  }
  fclose(events);
  /* Process-private helper: OS teardown avoids unbounded shutdown waits. */
  return error || script_error ? 1 : 0;
}
