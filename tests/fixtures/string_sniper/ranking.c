#include <stdio.h>

/* Compile-only fixture: all markers are printed as inert data. */

/* low */
static const char low_0[] = "ranking ordinary phrase a";
static const char low_1[] = "ranking ordinary phrase b";
static const char low_2[] = "ranking ordinary phrase c";
static const char low_3[] = "ranking ordinary phrase d";
static const char low_4[] = "ranking ordinary phrase e";
static const char low_5[] = "ranking ordinary phrase f";
static const char low_6[] = "ranking ordinary phrase g";
static const char low_7[] = "ranking ordinary phrase h";
static const char low_8[] = "ranking ordinary phrase i";
static const char low_9[] = "ranking ordinary phrase j";
static const char low_10[] = "ranking ordinary phrase k";
static const char low_11[] = "ranking ordinary phrase l";
static const char low_12[] = "ranking ordinary phrase m";
static const char low_13[] = "ranking ordinary phrase n";
static const char low_14[] = "ranking ordinary phrase o";
static const char low_15[] = "ranking ordinary phrase p";
static const char low_16[] = "ranking ordinary phrase q";
static const char low_17[] = "ranking ordinary phrase r";
static const char low_18[] = "ranking ordinary phrase s";
static const char low_19[] = "ranking ordinary phrase t";
static const char low_20[] = "ranking ordinary phrase u";
static const char low_21[] = "ranking ordinary phrase v";
static const char low_22[] = "ranking ordinary phrase w";
static const char low_23[] = "ranking ordinary phrase x";

/* medium */
static const char medium_0[] = "https://ranking.example.invalid/page0";
static const char medium_1[] = "https://ranking.example.invalid/page1";
static const char medium_2[] = "https://ranking.example.invalid/page2";
static const char medium_3[] = "https://ranking.example.invalid/page3";
static const char medium_4[] = "https://ranking.example.invalid/page4";
static const char medium_5[] = "https://ranking.example.invalid/page5";
static const char medium_6[] = "https://ranking.example.invalid/page6";
static const char medium_7[] = "https://ranking.example.invalid/page7";
static const char medium_8[] = "https://ranking.example.invalid/page8";
static const char medium_9[] = "https://ranking.example.invalid/page9";
static const char medium_10[] = "https://ranking.example.invalid/page10";
static const char medium_11[] = "https://ranking.example.invalid/page11";

/* high */
static const char high_0[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=0";
static const char high_1[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=1";
static const char high_2[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=2";
static const char high_3[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=3";
static const char high_4[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=4";
static const char high_5[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=5";
static const char high_6[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=6";
static const char high_7[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=7";
static const char high_8[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=8";
static const char high_9[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=9";
static const char high_10[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=10";
static const char high_11[] = "https://ranking.example.invalid/192.0.2.42/api_key/../cmd.exe?case=11";

static int emit_low(void) {
    int failed = 0;
    failed |= puts(low_0) < 0;
    failed |= puts(low_1) < 0;
    failed |= puts(low_2) < 0;
    failed |= puts(low_3) < 0;
    failed |= puts(low_4) < 0;
    failed |= puts(low_5) < 0;
    failed |= puts(low_6) < 0;
    failed |= puts(low_7) < 0;
    failed |= puts(low_8) < 0;
    failed |= puts(low_9) < 0;
    failed |= puts(low_10) < 0;
    failed |= puts(low_11) < 0;
    failed |= puts(low_12) < 0;
    failed |= puts(low_13) < 0;
    failed |= puts(low_14) < 0;
    failed |= puts(low_15) < 0;
    failed |= puts(low_16) < 0;
    failed |= puts(low_17) < 0;
    failed |= puts(low_18) < 0;
    failed |= puts(low_19) < 0;
    failed |= puts(low_20) < 0;
    failed |= puts(low_21) < 0;
    failed |= puts(low_22) < 0;
    failed |= puts(low_23) < 0;
    return failed;
}

static int emit_medium(void) {
    int failed = 0;
    failed |= puts(medium_0) < 0;
    failed |= puts(medium_1) < 0;
    failed |= puts(medium_2) < 0;
    failed |= puts(medium_3) < 0;
    failed |= puts(medium_4) < 0;
    failed |= puts(medium_5) < 0;
    failed |= puts(medium_6) < 0;
    failed |= puts(medium_7) < 0;
    failed |= puts(medium_8) < 0;
    failed |= puts(medium_9) < 0;
    failed |= puts(medium_10) < 0;
    failed |= puts(medium_11) < 0;
    return failed;
}

static int emit_high(void) {
    int failed = 0;
    failed |= puts(high_0) < 0;
    failed |= puts(high_1) < 0;
    failed |= puts(high_2) < 0;
    failed |= puts(high_3) < 0;
    failed |= puts(high_4) < 0;
    failed |= puts(high_5) < 0;
    failed |= puts(high_6) < 0;
    failed |= puts(high_7) < 0;
    failed |= puts(high_8) < 0;
    failed |= puts(high_9) < 0;
    failed |= puts(high_10) < 0;
    failed |= puts(high_11) < 0;
    return failed;
}

int main(void) {
    int failed = 0;
    failed |= emit_low();
    failed |= emit_medium();
    failed |= emit_high();
    return failed;
}
