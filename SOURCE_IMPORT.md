# Source import

This repository was extracted from the Bridgefu Vapi to Amazon Connect work in
`eisenzopf/bridgefu`.

- Historical import base commit: `60cf572b464cb737bb22ad723664a358becb1ff1`
- Historical imported working-tree patch digest: `40d862e33783567ed6c2f1bde7ea2a3aa18a27ede0608dc1d3e2da2499483c54`
- Historical imported Bridgefu Cargo.lock digest: `82c487bfd107ca92cfc8fb915ce6b841dc28c1dbafc6f57b296bb055bac7b14a`
- Required rvoip release: exact crates.io `0.3.8`
- License: MIT

Only the product-specific Lambda, Connect, Vapi, runtime, deployment, and test
assets were imported. Bridgefu itself remains an external, immutable build
input described by `bridgefu.lock.json`.

The original Bridgefu recipe is intentionally left untouched until this
standalone distribution passes remote AWS and live-call qualification.

The current AMI source is defined only by `bridgefu.lock.json`. It pins released
Bridgefu `v0.9.0` commit `e00db3289480f93c2783c57440a324e4438e29de`,
Cargo.lock SHA-256
`8bd0c889cc121076cd6d31bfa9058c763744f0c96022f5bb88b8f1d707a16ba9`, and
the exact crates.io rvoip 0.3.8 graph. If that lock changes, update this
provenance note only after verifying the remotely reachable commit and lock
digest; the historical import values above do not identify a release input.
