#include <stdio.h>

/* Compile-only fixture: all markers are printed as inert data. */

/* windows paths */
static const char windows_paths_0[] = "C:\\fixture\\sample.txt";
static const char windows_paths_1[] = "D:\\fixture\\data.bin";
static const char windows_paths_2[] = "c:\\fixture\\lower.txt";
static const char windows_paths_3[] = "\\\\fixture-server\\share\\sample.txt";
static const char windows_paths_4[] = "\\\\fixture-server\\share\\data.bin";
static const char windows_paths_5[] = "C:\\Windows\\System32\\fixture.exe";
static const char windows_paths_6[] = "C:\\fixture\\api_key.txt";
static const char windows_paths_7[] = "D:\\fixture\\token42.bin";
static const char windows_paths_8[] = "E:\\fixture\\secret.txt";
static const char windows_paths_9[] = "C:\\fixture\\password.txt";

/* unix paths */
static const char unix_paths_0[] = "/etc/fixture.conf";
static const char unix_paths_1[] = "/var/fixture/sample";
static const char unix_paths_2[] = "/tmp/fixture/sample";
static const char unix_paths_3[] = "/etc/fixture/token42";
static const char unix_paths_4[] = "/var/fixture/password";
static const char unix_paths_5[] = "/tmp/fixture/secret";
static const char unix_paths_6[] = "/etc/fixture/credential";
static const char unix_paths_7[] = "/var/fixture/api_key";
static const char unix_paths_8[] = "/tmp/fixture/../sample";
static const char unix_paths_9[] = "/tmp/fixture/cmd.exe";

/* configuration */
static const char configuration_0[] = "Software\\Fixture\\Settings";
static const char configuration_1[] = "CurrentVersion\\Fixture\\Settings";
static const char configuration_2[] = "SOFTWARE\\Fixture\\Token";
static const char configuration_3[] = "../fixture/sample";
static const char configuration_4[] = "..\\fixture\\sample";
static const char configuration_5[] = "../../fixture/token42";
static const char configuration_6[] = "..\\..\\fixture\\secret";
static const char configuration_7[] = "Software\\Fixture\\api_key";
static const char configuration_8[] = "CurrentVersion\\Fixture\\password";
static const char configuration_9[] = "../fixture/credential";

/* execution */
static const char execution_0[] = "cmd.exe /c echo fixture";
static const char execution_1[] = "CMD.EXE /c echo fixture";
static const char execution_2[] = "PowerShell -Command fixture";
static const char execution_3[] = "POWERSHELL -Command fixture";
static const char execution_4[] = "/bin/sh fixture";
static const char execution_5[] = "/bin/bash fixture";
static const char execution_6[] = "System32 fixture";
static const char execution_7[] = "cmd.exe /c echo token42";
static const char execution_8[] = "powershell fixture_secret";
static const char execution_9[] = "/bin/sh ../fixture/password";

static int emit_windows_paths(void) {
    int failed = 0;
    failed |= puts(windows_paths_0) < 0;
    failed |= puts(windows_paths_1) < 0;
    failed |= puts(windows_paths_2) < 0;
    failed |= puts(windows_paths_3) < 0;
    failed |= puts(windows_paths_4) < 0;
    failed |= puts(windows_paths_5) < 0;
    failed |= puts(windows_paths_6) < 0;
    failed |= puts(windows_paths_7) < 0;
    failed |= puts(windows_paths_8) < 0;
    failed |= puts(windows_paths_9) < 0;
    return failed;
}

static int emit_unix_paths(void) {
    int failed = 0;
    failed |= puts(unix_paths_0) < 0;
    failed |= puts(unix_paths_1) < 0;
    failed |= puts(unix_paths_2) < 0;
    failed |= puts(unix_paths_3) < 0;
    failed |= puts(unix_paths_4) < 0;
    failed |= puts(unix_paths_5) < 0;
    failed |= puts(unix_paths_6) < 0;
    failed |= puts(unix_paths_7) < 0;
    failed |= puts(unix_paths_8) < 0;
    failed |= puts(unix_paths_9) < 0;
    return failed;
}

static int emit_configuration(void) {
    int failed = 0;
    failed |= puts(configuration_0) < 0;
    failed |= puts(configuration_1) < 0;
    failed |= puts(configuration_2) < 0;
    failed |= puts(configuration_3) < 0;
    failed |= puts(configuration_4) < 0;
    failed |= puts(configuration_5) < 0;
    failed |= puts(configuration_6) < 0;
    failed |= puts(configuration_7) < 0;
    failed |= puts(configuration_8) < 0;
    failed |= puts(configuration_9) < 0;
    return failed;
}

static int emit_execution(void) {
    int failed = 0;
    failed |= puts(execution_0) < 0;
    failed |= puts(execution_1) < 0;
    failed |= puts(execution_2) < 0;
    failed |= puts(execution_3) < 0;
    failed |= puts(execution_4) < 0;
    failed |= puts(execution_5) < 0;
    failed |= puts(execution_6) < 0;
    failed |= puts(execution_7) < 0;
    failed |= puts(execution_8) < 0;
    failed |= puts(execution_9) < 0;
    return failed;
}

int main(void) {
    int failed = 0;
    failed |= emit_windows_paths();
    failed |= emit_unix_paths();
    failed |= emit_configuration();
    failed |= emit_execution();
    return failed;
}
