#include <stdio.h>

/* Compile-only fixture: all markers are printed as inert data. */

/* urls */
static const char urls_0[] = "https://updates.example.invalid/build42";
static const char urls_1[] = "http://telemetry.example.invalid/events";
static const char urls_2[] = "HTTPS://UPDATES.EXAMPLE.INVALID/BUILD42";
static const char urls_3[] = "HTTP://STATUS.EXAMPLE.INVALID/HEALTH";
static const char urls_4[] = "https://example.invalid/api/token42";
static const char urls_5[] = "https://example.invalid/login?password=fixture";
static const char urls_6[] = "https://example.invalid/../settings";
static const char urls_7[] = "https://example.invalid/cmd.exe";
static const char urls_8[] = "http://192.0.2.42/status";
static const char urls_9[] = "https://example.invalid:8443/api";

/* addresses */
static const char addresses_0[] = "192.0.2.1";
static const char addresses_1[] = "192.0.2.42";
static const char addresses_2[] = "192.0.2.254";
static const char addresses_3[] = "198.51.100.1";
static const char addresses_4[] = "198.51.100.42";
static const char addresses_5[] = "198.51.100.254";
static const char addresses_6[] = "203.0.113.1";
static const char addresses_7[] = "203.0.113.42";
static const char addresses_8[] = "203.0.113.254";
static const char addresses_9[] = "endpoint=192.0.2.42:443";

/* text boundaries */
static const char text_boundaries_0[] = "prefix https://example.invalid/path suffix";
static const char text_boundaries_1[] = "url=https://example.invalid/path";
static const char text_boundaries_2[] = "(https://example.invalid/path)";
static const char text_boundaries_3[] = "https://example.invalid/path#fragment";
static const char text_boundaries_4[] = "https://example.invalid/path?mode=demo";
static const char text_boundaries_5[] = "https://example.invalid/path with spaces";
static const char text_boundaries_6[] = "host 192.0.2.42 end";
static const char text_boundaries_7[] = "host=198.51.100.42;";
static const char text_boundaries_8[] = "[203.0.113.42]";
static const char text_boundaries_9[] = "192.0.2.42/24";

/* controls */
static const char controls_0[] = "ordinary greeting";
static const char controls_1[] = "example.invalid";
static const char controls_2[] = "ftp://example.invalid/file";
static const char controls_3[] = "mailto:fixture@example.invalid";
static const char controls_4[] = "https:/example.invalid";
static const char controls_5[] = "http:example.invalid";
static const char controls_6[] = "2001:db8::42";
static const char controls_7[] = "192.0.2";
static const char controls_8[] = "999.999.999.999";
static const char controls_9[] = "release42";

static int emit_urls(void) {
    int failed = 0;
    failed |= puts(urls_0) < 0;
    failed |= puts(urls_1) < 0;
    failed |= puts(urls_2) < 0;
    failed |= puts(urls_3) < 0;
    failed |= puts(urls_4) < 0;
    failed |= puts(urls_5) < 0;
    failed |= puts(urls_6) < 0;
    failed |= puts(urls_7) < 0;
    failed |= puts(urls_8) < 0;
    failed |= puts(urls_9) < 0;
    return failed;
}

static int emit_addresses(void) {
    int failed = 0;
    failed |= puts(addresses_0) < 0;
    failed |= puts(addresses_1) < 0;
    failed |= puts(addresses_2) < 0;
    failed |= puts(addresses_3) < 0;
    failed |= puts(addresses_4) < 0;
    failed |= puts(addresses_5) < 0;
    failed |= puts(addresses_6) < 0;
    failed |= puts(addresses_7) < 0;
    failed |= puts(addresses_8) < 0;
    failed |= puts(addresses_9) < 0;
    return failed;
}

static int emit_text_boundaries(void) {
    int failed = 0;
    failed |= puts(text_boundaries_0) < 0;
    failed |= puts(text_boundaries_1) < 0;
    failed |= puts(text_boundaries_2) < 0;
    failed |= puts(text_boundaries_3) < 0;
    failed |= puts(text_boundaries_4) < 0;
    failed |= puts(text_boundaries_5) < 0;
    failed |= puts(text_boundaries_6) < 0;
    failed |= puts(text_boundaries_7) < 0;
    failed |= puts(text_boundaries_8) < 0;
    failed |= puts(text_boundaries_9) < 0;
    return failed;
}

static int emit_controls(void) {
    int failed = 0;
    failed |= puts(controls_0) < 0;
    failed |= puts(controls_1) < 0;
    failed |= puts(controls_2) < 0;
    failed |= puts(controls_3) < 0;
    failed |= puts(controls_4) < 0;
    failed |= puts(controls_5) < 0;
    failed |= puts(controls_6) < 0;
    failed |= puts(controls_7) < 0;
    failed |= puts(controls_8) < 0;
    failed |= puts(controls_9) < 0;
    return failed;
}

int main(void) {
    int failed = 0;
    failed |= emit_urls();
    failed |= emit_addresses();
    failed |= emit_text_boundaries();
    failed |= emit_controls();
    return failed;
}
