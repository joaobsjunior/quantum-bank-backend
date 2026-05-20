#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gradle_version="9.2.1"
gradle_home="$script_dir/.gradle/local/gradle-$gradle_version"
gradle_zip="$script_dir/.gradle/local/gradle-$gradle_version-bin.zip"
gradle_url="https://services.gradle.org/distributions/gradle-$gradle_version-bin.zip"

if [[ ! -x "$gradle_home/bin/gradle" ]]; then
  mkdir -p "$script_dir/.gradle/local"
  if [[ ! -f "$gradle_zip" ]]; then
    curl -fL "$gradle_url" -o "$gradle_zip"
  fi
  rm -rf "$gradle_home"
  unzip -q "$gradle_zip" -d "$script_dir/.gradle/local"
fi

exec "$gradle_home/bin/gradle" "$@"
