#include <stdio.h>

/* Compile-only fixture: all markers are printed as inert data. */

/* lowercase */
static const char lowercase_0[] = "password=fixture42";
static const char lowercase_1[] = "passwd=fixture42";
static const char lowercase_2[] = "token=fixture42";
static const char lowercase_3[] = "secret=fixture42";
static const char lowercase_4[] = "credential=fixture42";
static const char lowercase_5[] = "api_key=fixture42";
static const char lowercase_6[] = "api-key=fixture42";

/* uppercase */
static const char uppercase_0[] = "PASSWORD=FIXTURE43";
static const char uppercase_1[] = "PASSWD=FIXTURE43";
static const char uppercase_2[] = "TOKEN=FIXTURE43";
static const char uppercase_3[] = "SECRET=FIXTURE43";
static const char uppercase_4[] = "CREDENTIAL=FIXTURE43";
static const char uppercase_5[] = "API_KEY=FIXTURE43";
static const char uppercase_6[] = "API-KEY=FIXTURE43";

/* embedded */
static const char embedded_0[] = "prefix_password_suffix";
static const char embedded_1[] = "prefix_passwd_suffix";
static const char embedded_2[] = "prefix_token_suffix";
static const char embedded_3[] = "prefix_secret_suffix";
static const char embedded_4[] = "prefix_credential_suffix";
static const char embedded_5[] = "prefix_api_key_suffix";
static const char embedded_6[] = "prefix_api-key_suffix";

/* combined */
static const char combined_0[] = "https://credentials.example.invalid/password/fixture44";
static const char combined_1[] = "https://credentials.example.invalid/passwd/fixture44";
static const char combined_2[] = "https://credentials.example.invalid/token/fixture44";
static const char combined_3[] = "https://credentials.example.invalid/secret/fixture44";
static const char combined_4[] = "https://credentials.example.invalid/credential/fixture44";
static const char combined_5[] = "https://credentials.example.invalid/api_key/fixture44";
static const char combined_6[] = "https://credentials.example.invalid/api-key/fixture44";

/* boundaries */
static const char boundaries_0[] = "\"password\": \"fixture45\"";
static const char boundaries_1[] = "\"passwd\": \"fixture45\"";
static const char boundaries_2[] = "\"token\": \"fixture45\"";
static const char boundaries_3[] = "\"secret\": \"fixture45\"";
static const char boundaries_4[] = "\"credential\": \"fixture45\"";
static const char boundaries_5[] = "\"api_key\": \"fixture45\"";
static const char boundaries_6[] = "\"api-key\": \"fixture45\"";

/* controls */
static const char controls_0[] = "ordinary greeting";
static const char controls_1[] = "release42";
static const char controls_2[] = "fixture only";
static const char controls_3[] = "pass phrase";
static const char controls_4[] = "api key";
static const char controls_5[] = "auth marker";
static const char controls_6[] = "configuration value";

static int emit_lowercase(void) {
    int failed = 0;
    failed |= puts(lowercase_0) < 0;
    failed |= puts(lowercase_1) < 0;
    failed |= puts(lowercase_2) < 0;
    failed |= puts(lowercase_3) < 0;
    failed |= puts(lowercase_4) < 0;
    failed |= puts(lowercase_5) < 0;
    failed |= puts(lowercase_6) < 0;
    return failed;
}

static int emit_uppercase(void) {
    int failed = 0;
    failed |= puts(uppercase_0) < 0;
    failed |= puts(uppercase_1) < 0;
    failed |= puts(uppercase_2) < 0;
    failed |= puts(uppercase_3) < 0;
    failed |= puts(uppercase_4) < 0;
    failed |= puts(uppercase_5) < 0;
    failed |= puts(uppercase_6) < 0;
    return failed;
}

static int emit_embedded(void) {
    int failed = 0;
    failed |= puts(embedded_0) < 0;
    failed |= puts(embedded_1) < 0;
    failed |= puts(embedded_2) < 0;
    failed |= puts(embedded_3) < 0;
    failed |= puts(embedded_4) < 0;
    failed |= puts(embedded_5) < 0;
    failed |= puts(embedded_6) < 0;
    return failed;
}

static int emit_combined(void) {
    int failed = 0;
    failed |= puts(combined_0) < 0;
    failed |= puts(combined_1) < 0;
    failed |= puts(combined_2) < 0;
    failed |= puts(combined_3) < 0;
    failed |= puts(combined_4) < 0;
    failed |= puts(combined_5) < 0;
    failed |= puts(combined_6) < 0;
    return failed;
}

static int emit_boundaries(void) {
    int failed = 0;
    failed |= puts(boundaries_0) < 0;
    failed |= puts(boundaries_1) < 0;
    failed |= puts(boundaries_2) < 0;
    failed |= puts(boundaries_3) < 0;
    failed |= puts(boundaries_4) < 0;
    failed |= puts(boundaries_5) < 0;
    failed |= puts(boundaries_6) < 0;
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
    return failed;
}

int main(void) {
    int failed = 0;
    failed |= emit_lowercase();
    failed |= emit_uppercase();
    failed |= emit_embedded();
    failed |= emit_combined();
    failed |= emit_boundaries();
    failed |= emit_controls();
    return failed;
}
