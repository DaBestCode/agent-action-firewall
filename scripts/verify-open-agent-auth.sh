#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
project_root=$(cd "$(dirname "$0")/.." && pwd)
lock="$project_root/upstream/open-agent-auth.lock.json"
commit=$(jq -er '.commit' "$lock")
version=$(jq -er '.artifactVersion' "$lock")
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid commit lock' >&2; exit 1; }
[[ "$version" == 0.1.0-beta.1-SNAPSHOT ]] || { echo 'Unreviewed upstream version' >&2; exit 1; }
cache="$project_root/.upstream/$commit"
receipt="$cache/build-receipt.json"
[[ -f "$receipt" ]] || { echo 'Build the pinned core first' >&2; exit 1; }
[[ $(jq -er '.commit' "$receipt") == "$commit" ]]
[[ $(jq -er '.artifactVersion' "$receipt") == "$version" ]]
jar="$cache/repository/com/alibaba/openagentauth/open-agent-auth-core/$version/open-agent-auth-core-$version.jar"
actual=$(shasum -a 256 "$jar" | cut -d ' ' -f 1)
[[ "$actual" == $(jq -er '.sha256' "$receipt") ]] || { echo 'Upstream JAR checksum mismatch' >&2; exit 1; }
[[ "$actual" == $(jq -er '.coreJarSha256' "$lock") ]] || { echo 'Upstream JAR differs from reviewed lock' >&2; exit 1; }
core_pom="$cache/repository/com/alibaba/openagentauth/open-agent-auth-core/$version/open-agent-auth-core-$version.pom"
parent_pom="$cache/repository/com/alibaba/openagentauth/open-agent-auth/$version/open-agent-auth-$version.pom"
[[ $(shasum -a 256 "$core_pom" | cut -d ' ' -f 1) == $(jq -er '.corePomSha256' "$lock") ]]
[[ $(shasum -a 256 "$parent_pom" | cut -d ' ' -f 1) == $(jq -er '.parentPomSha256' "$lock") ]]
offline=""
if [[ ${1:-} == --offline ]]; then offline=-o; fi
if [[ -n ${1:-} && ${1:-} != --offline ]]; then echo 'Unknown option' >&2; exit 1; fi
mvn ${offline:+"$offline"} -B -ntp -nsu -f "$project_root/pom.xml" \
    -Popen-agent-auth "-Dmaven.repo.local=$cache/repository" verify
