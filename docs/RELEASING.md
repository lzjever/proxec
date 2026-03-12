# Releasing proxec

## Versioning

`proxec` uses semver tags in the form `vX.Y.Z`.

## Pre-release checklist

1. Update `CHANGELOG.md`
2. Run:
   ```bash
   cargo test
   cargo build --release
   ./scripts/package-release.sh
   ```
3. Manually smoke test:
   - `./target/release/proxec --help`
   - `./target/release/proxec --version`
   - `./target/release/proxec --proxy socks://127.0.0.1:21089 antigravity`
   - close the proxied GUI app and confirm `proxec` exits
   - `Ctrl-C` the proxied app and confirm `proxec` exits cleanly

## Cut a release

```bash
version=0.1.1
git tag -a "v${version}" -m "proxec v${version}"
git push origin "v${version}"
```

The `release.yml` workflow will build the Linux release tarball and publish it to GitHub Releases.
