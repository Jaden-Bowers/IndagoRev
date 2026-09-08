#include <stdio.h>
static volatile unsigned input=7;
int main(void) {
    unsigned value=input*6;
    printf("indago-rr-fixture:%u\n",value);
    return value==42?0:1;
}
