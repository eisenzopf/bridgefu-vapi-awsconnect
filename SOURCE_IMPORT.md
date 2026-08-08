# Source import

This repository was extracted from the Bridgefu Vapi to Amazon Connect work in
`eisenzopf/bridgefu`.

- Base commit: `60cf572b464cb737bb22ad723664a358becb1ff1`
- Imported working-tree patch digest: `40d862e33783567ed6c2f1bde7ea2a3aa18a27ede0608dc1d3e2da2499483c54`
- Bridgefu Cargo.lock digest: `82c487bfd107ca92cfc8fb915ce6b841dc28c1dbafc6f57b296bb055bac7b14a`
- Required rvoip release: exact crates.io `0.3.7`
- License: MIT

Only the product-specific Lambda, Connect, Vapi, runtime, deployment, and test
assets were imported. Bridgefu itself remains an external, immutable build
input described by `bridgefu.lock.json`.

The original Bridgefu recipe is intentionally left untouched until this
standalone distribution passes remote AWS and live-call qualification.

The base commit still contains rvoip 0.3.5. `bridgefu.lock.json` therefore
marks public AMI publication as blocked until the current crates.io 0.3.7 core
work is committed and reachable from the Bridgefu remote.
