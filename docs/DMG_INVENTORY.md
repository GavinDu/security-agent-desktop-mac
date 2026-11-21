# Single-candidate developer DMG verification — #85

Parent: latest Epic #10 (release/lifecycle). Origin: working
Foundation Epic #8 and completed strict developer DMG acceptance #11/#62.
Production Developer ID and notarization remain open in #47.

## Release-gate invariant

The GitHub Actions macOS 15 job builds an ad-hoc **development-only**
`.dmg` and uploads every `bundle/dmg/*.dmg` file. The verification
script must inspect **the exact unique artifact** that is eligible for
upload, not silently verify the first candidate and upload a second.

`scripts/dmg-inventory.sh` is a Bash 3.2-compatible helper sourced by
`verify-macos-bundle.sh`. It uses null-delimited `find -print0` and
`read -r -d ''`, supporting spaces or newlines in filenames. Verification
fails closed when the DMG directory has zero, multiple or symlinked
`*.dmg` candidates, or when the mounted volume has zero, multiple
or symlinked `*.app` root candidates. An empty DMG is invalid.

It then retains the same strict requirements: canonical app bundle
identifier, actual Apple Silicon arm64 Mach-O, bundled icon, ad-hoc-only
bundle signature and no entitlements. The read-only volume detaches on
both success and failure using the existing EXIT trap.

## Test coverage and limitations

`npm run test:foundation` executes Node fixtures on Linux and macOS
for missing, duplicate, symlinked, directory-versus-file and
space/newline paths. These tests validate the inventory helper and
that the actual mounted-DMG verifier invokes it.

Only the `macos-15` CI job mounts and verifies a real Tauri-generated
DMG and uploads the resulting artifact. A green fixture test is not
proof of Developer ID signing, Apple notarization, Gatekeeper trust or
installation on an actual Mac Mini. Parent #47, #12 and #55 remain OPEN.

The helper rejects symlinks to the candidate files and mount path;
it does not establish trust for unrelated files in the workspace or
fix privileged helper packaging. If future CI emits more than one
architectural DMG, the build must deliberately split verification and
upload into individually gated artifacts, not silently weaken the
single-candidate invariant.
