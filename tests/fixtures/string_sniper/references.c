#include <stdio.h>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

/* One shared array, with forty distinct referencing functions. */
static const char shared_marker[] = "https://references.example.invalid/shared42";

NOINLINE int reference_00(void) { return puts(shared_marker); }
NOINLINE int reference_01(void) { return puts(shared_marker); }
NOINLINE int reference_02(void) { return puts(shared_marker); }
NOINLINE int reference_03(void) { return puts(shared_marker); }
NOINLINE int reference_04(void) { return puts(shared_marker); }
NOINLINE int reference_05(void) { return puts(shared_marker); }
NOINLINE int reference_06(void) { return puts(shared_marker); }
NOINLINE int reference_07(void) { return puts(shared_marker); }
NOINLINE int reference_08(void) { return puts(shared_marker); }
NOINLINE int reference_09(void) { return puts(shared_marker); }
NOINLINE int reference_10(void) { return puts(shared_marker); }
NOINLINE int reference_11(void) { return puts(shared_marker); }
NOINLINE int reference_12(void) { return puts(shared_marker); }
NOINLINE int reference_13(void) { return puts(shared_marker); }
NOINLINE int reference_14(void) { return puts(shared_marker); }
NOINLINE int reference_15(void) { return puts(shared_marker); }
NOINLINE int reference_16(void) { return puts(shared_marker); }
NOINLINE int reference_17(void) { return puts(shared_marker); }
NOINLINE int reference_18(void) { return puts(shared_marker); }
NOINLINE int reference_19(void) { return puts(shared_marker); }
NOINLINE int reference_20(void) { return puts(shared_marker); }
NOINLINE int reference_21(void) { return puts(shared_marker); }
NOINLINE int reference_22(void) { return puts(shared_marker); }
NOINLINE int reference_23(void) { return puts(shared_marker); }
NOINLINE int reference_24(void) { return puts(shared_marker); }
NOINLINE int reference_25(void) { return puts(shared_marker); }
NOINLINE int reference_26(void) { return puts(shared_marker); }
NOINLINE int reference_27(void) { return puts(shared_marker); }
NOINLINE int reference_28(void) { return puts(shared_marker); }
NOINLINE int reference_29(void) { return puts(shared_marker); }
NOINLINE int reference_30(void) { return puts(shared_marker); }
NOINLINE int reference_31(void) { return puts(shared_marker); }
NOINLINE int reference_32(void) { return puts(shared_marker); }
NOINLINE int reference_33(void) { return puts(shared_marker); }
NOINLINE int reference_34(void) { return puts(shared_marker); }
NOINLINE int reference_35(void) { return puts(shared_marker); }
NOINLINE int reference_36(void) { return puts(shared_marker); }
NOINLINE int reference_37(void) { return puts(shared_marker); }
NOINLINE int reference_38(void) { return puts(shared_marker); }
NOINLINE int reference_39(void) { return puts(shared_marker); }

int main(void) {
    int failed = 0;
    failed |= reference_00() < 0;
    failed |= reference_01() < 0;
    failed |= reference_02() < 0;
    failed |= reference_03() < 0;
    failed |= reference_04() < 0;
    failed |= reference_05() < 0;
    failed |= reference_06() < 0;
    failed |= reference_07() < 0;
    failed |= reference_08() < 0;
    failed |= reference_09() < 0;
    failed |= reference_10() < 0;
    failed |= reference_11() < 0;
    failed |= reference_12() < 0;
    failed |= reference_13() < 0;
    failed |= reference_14() < 0;
    failed |= reference_15() < 0;
    failed |= reference_16() < 0;
    failed |= reference_17() < 0;
    failed |= reference_18() < 0;
    failed |= reference_19() < 0;
    failed |= reference_20() < 0;
    failed |= reference_21() < 0;
    failed |= reference_22() < 0;
    failed |= reference_23() < 0;
    failed |= reference_24() < 0;
    failed |= reference_25() < 0;
    failed |= reference_26() < 0;
    failed |= reference_27() < 0;
    failed |= reference_28() < 0;
    failed |= reference_29() < 0;
    failed |= reference_30() < 0;
    failed |= reference_31() < 0;
    failed |= reference_32() < 0;
    failed |= reference_33() < 0;
    failed |= reference_34() < 0;
    failed |= reference_35() < 0;
    failed |= reference_36() < 0;
    failed |= reference_37() < 0;
    failed |= reference_38() < 0;
    failed |= reference_39() < 0;
    return failed;
}
