#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gradle_version="9.2.1"
gradle_sha256="72f44c9f8ebcb1af43838f45ee5c4aa9c5444898b3468ab3f4af7b6076c5bc3f"
gradle_home="$script_dir/.gradle/local/gradle-$gradle_version"
gradle_zip="$script_dir/.gradle/local/gradle-$gradle_version-bin.zip"
gradle_url="https://services.gradle.org/distributions/gradle-$gradle_version-bin.zip"

verify_gradle_zip() {
  local actual
  actual="$(shasum -a 256 "$gradle_zip" | awk '{print $1}')"
  [[ "$actual" == "$gradle_sha256" ]]
}

if [[ ! -x "$gradle_home/bin/gradle" ]]; then
  mkdir -p "$script_dir/.gradle/local"
  if [[ ! -f "$gradle_zip" ]] || ! verify_gradle_zip; then
    rm -f "$gradle_zip"
    curl -fL "$gradle_url" -o "$gradle_zip"
  fi
  if ! verify_gradle_zip; then
    echo "Gradle distribution checksum verification failed: $gradle_zip" >&2
    exit 1
  fi
  rm -rf "$gradle_home"
  unzip -q "$gradle_zip" -d "$script_dir/.gradle/local"
fi

exec "$gradle_home/bin/gradle" "$@"
