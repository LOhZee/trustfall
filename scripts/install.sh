#!/usr/bin/env bash
set -euo pipefail

version="${1:?release version is required}"
expected_sha="${2:?expected SHA-256 is required}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid TrustFall release version" >&2
  exit 1
fi
if [[ ! "$expected_sha" =~ ^[a-fA-F0-9]{64}$ ]]; then
  echo "expected SHA-256 must be 64 hexadecimal characters" >&2
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) artifact="trustfall_${version#v}_linux_amd64.tar.gz" ;;
  Linux-aarch64|Linux-arm64) artifact="trustfall_${version#v}_linux_arm64.tar.gz" ;;
  *) echo "unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

temp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
if [[ ! -d "$temp_root" || ! -w "$temp_root" ]]; then
  echo "temporary directory is unavailable or not writable: $temp_root" >&2
  exit 1
fi
for command in curl sha256sum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required installer command is missing: $command" >&2
    exit 1
  fi
done

install_root="$(mktemp -d "$temp_root/trustfall-action.XXXXXX")"
archive="$install_root/$artifact"
mkdir "$install_root/bin"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "$archive" "https://github.com/LOhZee/trustfall/releases/download/$version/$artifact"
printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check --status
tar --extract --gzip --file "$archive" --directory "$install_root/bin" trustfall
chmod 0755 "$install_root/bin/trustfall"
"$install_root/bin/trustfall" version --json >/dev/null
printf '%s\n' "$install_root/bin" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
