#include <stdio.h>

/* Distinct equal-score strings support multi-page and text-search inspection. */
static const char page_000[] = "https://pagination.example.invalid/page000";
static const char page_001[] = "https://pagination.example.invalid/page001";
static const char page_002[] = "https://pagination.example.invalid/page002";
static const char page_003[] = "https://pagination.example.invalid/page003";
static const char page_004[] = "https://pagination.example.invalid/page004";
static const char page_005[] = "https://pagination.example.invalid/page005";
static const char page_006[] = "https://pagination.example.invalid/page006";
static const char page_007[] = "https://pagination.example.invalid/page007";
static const char page_008[] = "https://pagination.example.invalid/page008";
static const char page_009[] = "https://pagination.example.invalid/page009";
static const char page_010[] = "https://pagination.example.invalid/page010";
static const char page_011[] = "https://pagination.example.invalid/page011";
static const char page_012[] = "https://pagination.example.invalid/page012";
static const char page_013[] = "https://pagination.example.invalid/page013";
static const char page_014[] = "https://pagination.example.invalid/page014";
static const char page_015[] = "https://pagination.example.invalid/page015";
static const char page_016[] = "https://pagination.example.invalid/page016";
static const char page_017[] = "https://pagination.example.invalid/page017";
static const char page_018[] = "https://pagination.example.invalid/page018";
static const char page_019[] = "https://pagination.example.invalid/page019";
static const char page_020[] = "https://pagination.example.invalid/page020";
static const char page_021[] = "https://pagination.example.invalid/page021";
static const char page_022[] = "https://pagination.example.invalid/page022";
static const char page_023[] = "https://pagination.example.invalid/page023";
static const char page_024[] = "https://pagination.example.invalid/page024";
static const char page_025[] = "https://pagination.example.invalid/page025";
static const char page_026[] = "https://pagination.example.invalid/page026";
static const char page_027[] = "https://pagination.example.invalid/page027";
static const char page_028[] = "https://pagination.example.invalid/page028";
static const char page_029[] = "https://pagination.example.invalid/page029";
static const char page_030[] = "https://pagination.example.invalid/page030";
static const char page_031[] = "https://pagination.example.invalid/page031";
static const char page_032[] = "https://pagination.example.invalid/page032";
static const char page_033[] = "https://pagination.example.invalid/page033";
static const char page_034[] = "https://pagination.example.invalid/page034";
static const char page_035[] = "https://pagination.example.invalid/page035";
static const char page_036[] = "https://pagination.example.invalid/page036";
static const char page_037[] = "https://pagination.example.invalid/page037";
static const char page_038[] = "https://pagination.example.invalid/page038";
static const char page_039[] = "https://pagination.example.invalid/page039";
static const char page_040[] = "https://pagination.example.invalid/page040";
static const char page_041[] = "https://pagination.example.invalid/page041";
static const char page_042[] = "https://pagination.example.invalid/page042";
static const char page_043[] = "https://pagination.example.invalid/page043";
static const char page_044[] = "https://pagination.example.invalid/page044";
static const char page_045[] = "https://pagination.example.invalid/page045";
static const char page_046[] = "https://pagination.example.invalid/page046";
static const char page_047[] = "https://pagination.example.invalid/page047";
static const char page_048[] = "https://pagination.example.invalid/page048";
static const char page_049[] = "https://pagination.example.invalid/page049";
static const char page_050[] = "https://pagination.example.invalid/page050";
static const char page_051[] = "https://pagination.example.invalid/page051";
static const char page_052[] = "https://pagination.example.invalid/page052";
static const char page_053[] = "https://pagination.example.invalid/page053";
static const char page_054[] = "https://pagination.example.invalid/page054";
static const char page_055[] = "https://pagination.example.invalid/page055";
static const char page_056[] = "https://pagination.example.invalid/page056";
static const char page_057[] = "https://pagination.example.invalid/page057";
static const char page_058[] = "https://pagination.example.invalid/page058";
static const char page_059[] = "https://pagination.example.invalid/page059";
static const char page_060[] = "https://pagination.example.invalid/page060";
static const char page_061[] = "https://pagination.example.invalid/page061";
static const char page_062[] = "https://pagination.example.invalid/page062";
static const char page_063[] = "https://pagination.example.invalid/page063";
static const char page_064[] = "https://pagination.example.invalid/page064";
static const char page_065[] = "https://pagination.example.invalid/page065";
static const char page_066[] = "https://pagination.example.invalid/page066";
static const char page_067[] = "https://pagination.example.invalid/page067";
static const char page_068[] = "https://pagination.example.invalid/page068";
static const char page_069[] = "https://pagination.example.invalid/page069";
static const char page_070[] = "https://pagination.example.invalid/page070";
static const char page_071[] = "https://pagination.example.invalid/page071";
static const char page_072[] = "https://pagination.example.invalid/page072";
static const char page_073[] = "https://pagination.example.invalid/page073";
static const char page_074[] = "https://pagination.example.invalid/page074";
static const char page_075[] = "https://pagination.example.invalid/page075";
static const char page_076[] = "https://pagination.example.invalid/page076";
static const char page_077[] = "https://pagination.example.invalid/page077";
static const char page_078[] = "https://pagination.example.invalid/page078";
static const char page_079[] = "https://pagination.example.invalid/page079";
/* A long value supports inspection with a small max_output_bytes budget. */
static const char long_marker[] =
    "https://pagination.example.invalid/long42/"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext"
    "longtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtextlongtext";

int main(void) {
    puts(page_000);
    puts(page_001);
    puts(page_002);
    puts(page_003);
    puts(page_004);
    puts(page_005);
    puts(page_006);
    puts(page_007);
    puts(page_008);
    puts(page_009);
    puts(page_010);
    puts(page_011);
    puts(page_012);
    puts(page_013);
    puts(page_014);
    puts(page_015);
    puts(page_016);
    puts(page_017);
    puts(page_018);
    puts(page_019);
    puts(page_020);
    puts(page_021);
    puts(page_022);
    puts(page_023);
    puts(page_024);
    puts(page_025);
    puts(page_026);
    puts(page_027);
    puts(page_028);
    puts(page_029);
    puts(page_030);
    puts(page_031);
    puts(page_032);
    puts(page_033);
    puts(page_034);
    puts(page_035);
    puts(page_036);
    puts(page_037);
    puts(page_038);
    puts(page_039);
    puts(page_040);
    puts(page_041);
    puts(page_042);
    puts(page_043);
    puts(page_044);
    puts(page_045);
    puts(page_046);
    puts(page_047);
    puts(page_048);
    puts(page_049);
    puts(page_050);
    puts(page_051);
    puts(page_052);
    puts(page_053);
    puts(page_054);
    puts(page_055);
    puts(page_056);
    puts(page_057);
    puts(page_058);
    puts(page_059);
    puts(page_060);
    puts(page_061);
    puts(page_062);
    puts(page_063);
    puts(page_064);
    puts(page_065);
    puts(page_066);
    puts(page_067);
    puts(page_068);
    puts(page_069);
    puts(page_070);
    puts(page_071);
    puts(page_072);
    puts(page_073);
    puts(page_074);
    puts(page_075);
    puts(page_076);
    puts(page_077);
    puts(page_078);
    puts(page_079);
    puts(long_marker);
    return 0;
}
