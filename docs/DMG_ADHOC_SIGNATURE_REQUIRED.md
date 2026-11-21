# R01.2 / #119 — Require an ad-hoc seal on mounted developer DMG app

New independent P0 under latest successor Epic #10 only, origin working Epic #8 and verified #62/#85. Production Developer ID/notarization #47 remains OPEN.

The mounted verifier previously allowed completely unsigned app bundles through a fallback branch. The new verifier requires /usr/bin/codesign --display success, an exact standalone Signature=adhoc line, /usr/bin/codesign --verify --strict on the same uniquely selected mounted app, and fail-closed entitlement extraction with no elevated entitlements. All errors remain generic; raw codesign diagnostics are not output. Strict Bash 3.2 signature policy tests exercise ad-hoc vs unsigned/Developer ID/spoofed text. Frontend, rustfmt, locked Linux Rust and native macOS-15 locked Rust + mounted developer DMG verifier and artifact upload must pass exact current PR head before merge.

This does not perform notarization, access physical Mac UI or borrow third-party signing assets.
