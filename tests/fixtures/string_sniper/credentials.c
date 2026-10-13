#include <stdio.h>

/* Synthetic markers; these contain no real credentials. */
static const char password_marker[] = "password=fixture42";
static const char passwd_marker[] = "passwd=fixture43";
static const char token_marker[] = "TOKEN=fixture44";
static const char secret_marker[] = "secret=fixture45";
static const char credential_marker[] = "credential=fixture46";
static const char api_key_marker[] = "api_key=fixture47";
static const char api_dash_key_marker[] = "api-key=fixture48";
static const char mixed_marker[] = "release42";
static const char plain_marker[] = "ordinary greeting";

int main(void) {
    puts(password_marker);
    puts(passwd_marker);
    puts(token_marker);
    puts(secret_marker);
    puts(credential_marker);
    puts(api_key_marker);
    puts(api_dash_key_marker);
    puts(mixed_marker);
    puts(plain_marker);
    return 0;
}
