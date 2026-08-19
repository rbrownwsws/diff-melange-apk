#!/usr/bin/env bash
set -euo pipefail

old="${1}"
new="${2}"

echo_summary () {
   echo "${1}" >> "${GITHUB_STEP_SUMMARY}"
}

get_pkginfo () {
  tar xOf "${1}" '.PKGINFO' 2> /dev/null
}

# Replace commit hash with something static so commits that do not affect the
# package do not count as different (e.g. edits to README).
strip_pkginfo_commit () {
  awk \
    '
      BEGIN { FS=OFS=" = " }
      $1 ~ /^commit$/ {
        print $1, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        next
      }
      { print $1, $2 }
    ' \
    <(printf '%s' "${1}")
}

get_build_env() {
  tar xOf "${1}" '.melange.yaml' 2> /dev/null | yq '.environment.contents.packages[]'
}

package_changed="false"

old_pkginfo="$(get_pkginfo "${old}")"
new_pkginfo="$(get_pkginfo "${new}")"

old_pkginfo_stripped="$(strip_pkginfo_commit "${old_pkginfo}")"
new_pkginfo_stripped="$(strip_pkginfo_commit "${new_pkginfo}")"

if [[ "${old_pkginfo_stripped}" == "${new_pkginfo_stripped}" ]]; then
  echo_summary '# Package Info Identical'
else
  echo_summary '# Package Info Differs'

  echo_summary '```diff'
  diff -u \
    -L "old/.PKGINFO" \
    -L "new/.PKGINFO" \
    <(echo "${old_pkginfo_stripped}") \
    <(echo "${new_pkginfo_stripped}") \
    >> "${GITHUB_STEP_SUMMARY}" || true
  echo_summary '```'
  echo_summary ''

  package_changed="true"
fi

echo_summary '<details>'
echo_summary '<summary>Old .PKGINFO</summary>'
echo_summary ''
echo_summary '```ini'
echo_summary "${old_pkginfo}"
echo_summary '```'
echo_summary '</details>'
echo_summary ''

echo_summary '<details>'
echo_summary '<summary>New .PKGINFO</summary>'
echo_summary ''
echo_summary '```ini'
echo_summary "${new_pkginfo}"
echo_summary '```'
echo_summary '</details>'
echo_summary ''

old_build_env=$(get_build_env "${old}")
new_build_env=$(get_build_env "${new}")

if [[ "${old_build_env}" == "${new_build_env}" ]]; then
  echo_summary '# Build Environment Identical'
else
  echo_summary '# Build Environment Differs'

  awk -f "${GITHUB_ACTION_PATH}/diff-melange-env.awk" \
    <(echo "${old_build_env}") \
    <(echo "${new_build_env}") \
    >> "${GITHUB_STEP_SUMMARY}"

  package_changed="true"
fi

echo "package_changed=${package_changed}" >> "${GITHUB_OUTPUT}"
