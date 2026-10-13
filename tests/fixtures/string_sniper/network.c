#include <stdio.h>

/* Reserved example endpoints are string data only. */
static const char https_endpoint[] = "https://updates.example.invalid/build42";
static const char http_endpoint[] = "http://telemetry.example.invalid/events";
static const char ipv4_endpoint[] = "192.0.2.42";
static const char upper_endpoint[] = "HTTPS://UPDATES.EXAMPLE.INVALID/BUILD42";
static const char plain_text[] = "ordinary greeting";

int main(void) {
    puts(https_endpoint);
    puts(http_endpoint);
    puts(ipv4_endpoint);
    puts(upper_endpoint);
    puts(plain_text);
    return 0;
}
