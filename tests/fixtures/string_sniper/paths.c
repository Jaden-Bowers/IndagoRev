#include <stdio.h>

/* Paths and commands are printed as data; nothing opens or executes them. */
static const char drive_path[] = "C:\\fixture\\sample.txt";
static const char unc_path[] = "\\\\fixture-server\\share\\sample.txt";
static const char etc_path[] = "/etc/fixture.conf";
static const char var_path[] = "/var/fixture/sample";
static const char tmp_path[] = "/tmp/fixture/sample";
static const char registry_path[] = "Software\\Fixture\\CurrentVersion\\Settings";
static const char relative_unix[] = "../fixture/sample";
static const char relative_windows[] = "..\\fixture\\sample";
static const char cmd_marker[] = "cmd.exe /c echo fixture";
static const char powershell_marker[] = "PowerShell -Command fixture";
static const char shell_marker[] = "/bin/sh fixture";
static const char bash_marker[] = "/bin/bash fixture";
static const char system_marker[] = "C:\\Windows\\System32\\fixture.exe";

int main(void) {
    puts(drive_path);
    puts(unc_path);
    puts(etc_path);
    puts(var_path);
    puts(tmp_path);
    puts(registry_path);
    puts(relative_unix);
    puts(relative_windows);
    puts(cmd_marker);
    puts(powershell_marker);
    puts(shell_marker);
    puts(bash_marker);
    puts(system_marker);
    return 0;
}
