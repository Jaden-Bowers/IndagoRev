# Integrated AIRECE implementation

Imported from the existing AIRECE proof of concept at revision
23997f2e7430baff1d4d5e087e4e1bda786c45f0 with the owner's authorization.
The existing copyright notice is retained; no new license is assigned.

IndagoRev builds these sources directly via `cmake/IntegratedAirece.cmake`.
The former CLI entry is renamed at compile time and dispatched by the internal
`__airece` mode of `indago.exe`. The public platform surface is unchanged.
This retains the existing operation handlers and cancellation isolation without
an external AIRECE application dependency. Upstream semantic libraries and their
third-party notices retain their own identities and licenses.
