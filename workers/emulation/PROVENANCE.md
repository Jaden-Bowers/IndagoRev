# Bounded emulation worker

Unicorn 2.1.4, source archive SHA-256
`ea8863f095a0136388694e5a6063afd9bb7650e30243dd6251af59c5ce5601f4`.
Source: https://github.com/unicorn-engine/unicorn/tree/2.1.4
The separate worker links GPL-2.0 Unicorn; distribute it under GPL-2.0 with
corresponding worker and pinned upstream source. The MIT controller communicates
through bounded JSON; it does not link Unicorn. Upstream notices accompany it.
Only upstream x86 CPU emulation is enabled; there is no host OS/API passthrough.
