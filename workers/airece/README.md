# XAIR integration

XAIR and XAIR_CFG are built as static libraries and linked into `indago`. There
is no separate AIRECE executable. Internal `__airece` and `__xair` modes of the
same binary isolate static analysis and allow process-tree cancellation.
The integration preserves
XAIR load/CFG status, completeness, semantic coverage, unresolved indirects,
and hexadecimal addresses in its result record.
