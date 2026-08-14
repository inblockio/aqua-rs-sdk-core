#!/usr/bin/env bash
# The only publish path for aqua-rs-sdk-core. See RELEASE.md.
set -euo pipefail

usage() {
  echo "usage: $0 [--dry-run] [--yes] X.Y.Z" >&2
  exit 2
}

dry_run=0
assume_yes=0
version=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --yes) assume_yes=1 ;;
    -h|--help) usage ;;
    *)
      if [ -n "$version" ]; then usage; fi
      version="$arg"
      ;;
  esac
done
[ -n "$version" ] || usage
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "error: version must be X.Y.Z, got '$version'" >&2
  exit 2
}

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
crate="aqua-rs-sdk-core"
tag="v$version"

current="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
echo "crate:    $crate"
echo "current:  $current"
echo "release:  $version"
echo "tag:      $tag"

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
  echo "error: must be on main (not $(git rev-parse --abbrev-ref HEAD))" >&2
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is dirty" >&2
  git status -sb >&2
  exit 1
fi
git fetch origin
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
  echo "error: HEAD is not origin/main" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "error: tag $tag already exists locally" >&2
  exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "error: tag $tag already exists on origin" >&2
  exit 1
fi

if [ "$version" = "$current" ]; then
  echo "error: $version is already Cargo.toml; bump to a new number" >&2
  exit 1
fi

echo "checking crates.io for $crate $version..."
code="$(curl -sS -o /tmp/crate-ver.json -w '%{http_code}' \
  "https://crates.io/api/v1/crates/$crate/$version")"
if [ "$code" = "200" ]; then
  echo "error: $crate $version is already on crates.io" >&2
  exit 1
fi
if [ "$code" != "404" ]; then
  echo "error: crates.io returned HTTP $code looking up $crate $version" >&2
  exit 1
fi

if ! grep -qE "^## $version( |$)" CHANGELOG.md; then
  echo "error: CHANGELOG.md has no '## $version' heading" >&2
  echo "       add the notes first, then re-run." >&2
  exit 1
fi

sdk_dir="$(cd "$root/../aqua-rs-sdk" 2>/dev/null && pwd || true)"
if [ -z "$sdk_dir" ]; then
  echo "error: sibling ../aqua-rs-sdk is required (compat is the subset proof)" >&2
  exit 1
fi
sdk_sha="$(git -C "$sdk_dir" rev-parse HEAD)"
sdk_branch="$(git -C "$sdk_dir" rev-parse --abbrev-ref HEAD)"
echo "compat against aqua-rs-sdk $sdk_branch @$sdk_sha"

echo "==> cargo test"
cargo test
echo "==> compat-tests"
cargo test --manifest-path compat-tests/Cargo.toml
echo "==> verify-templates"
cargo run --features native --bin verify-templates
echo "==> publish dry-run (current tree; version bump is next)"
cargo publish --dry-run --allow-dirty

if [ "$dry_run" -eq 1 ]; then
  echo "dry-run complete. would bump $current -> $version, tag $tag, publish."
  exit 0
fi

if [ "$assume_yes" -eq 0 ]; then
  echo
  echo "About to: bump $current -> $version, commit, tag $tag, push, cargo publish."
  echo "This is the timed gate. Ctrl-C to abort."
  read -r -p "Press enter to publish $crate $version: "
fi

# Bump only the package version, not dependency versions.
python3 - "$version" <<'PY'
import pathlib, sys
version = sys.argv[1]
toml = pathlib.Path("Cargo.toml")
text = toml.read_text()
old = None
out = []
seen = False
for line in text.splitlines(keepends=True):
    if not seen and line.startswith("version = "):
        old = line
        line = f'version = "{version}"\n'
        seen = True
    out.append(line)
if not seen:
    raise SystemExit("Cargo.toml has no package version line")
toml.write_text("".join(out))
lock = pathlib.Path("Cargo.lock")
lt = lock.read_text()
# First aqua-rs-sdk-core stanza is the package itself.
needle = 'name = "aqua-rs-sdk-core"\nversion = "'
i = lt.find(needle)
if i < 0:
    raise SystemExit("Cargo.lock missing aqua-rs-sdk-core stanza")
j = lt.find('"', i + len(needle))
old_ver = lt[i + len(needle) : j]
lt = lt[: i + len(needle)] + version + lt[j:]
lock.write_text(lt)
print(f"Cargo.toml/Cargo.lock: {old_ver} -> {version}")
PY

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "$(cat <<EOF
release: $crate $version

Subset-proof: aqua-rs-sdk ${sdk_sha} (${sdk_branch})
Compat suite + verify-templates + publish dry-run were run by
scripts/release.sh before this commit.
EOF
)"

# Re-dry-run on the bumped tree so we never upload a package we did not verify.
cargo publish --dry-run

git tag -a "$tag" -m "$crate $version"
git push origin main
git push origin "$tag"
cargo publish

echo "published $crate $version  tag $tag"
echo "crates.io: https://crates.io/crates/$crate/$version"
