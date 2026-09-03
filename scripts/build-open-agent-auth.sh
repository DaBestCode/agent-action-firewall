#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Export exactly the locked Git tree. Never build or modify the user's source checkout.
project_root=$(cd "$(dirname "$0")/.." && pwd)
source_repo=${1:?Usage: bash scripts/build-open-agent-auth.sh /path/to/local/upstream [--offline]}
offline=""
if [[ ${2:-} == --offline ]]; then offline=-o; fi
if [[ -n ${2:-} && ${2:-} != --offline ]]; then echo 'Unknown option' >&2; exit 1; fi
lock="$project_root/upstream/open-agent-auth.lock.json"
commit=$(jq -er '.commit' "$lock")
version=$(jq -er '.artifactVersion' "$lock")
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid commit lock' >&2; exit 1; }
[[ "$version" == 0.1.0-beta.1-SNAPSHOT ]] || { echo 'Unreviewed upstream version' >&2; exit 1; }
[[ $(git -C "$source_repo" rev-parse "$commit^{commit}") == "$commit" ]]
[[ $(java -version 2>&1 | head -1) == *'"17.'* ]] || { echo 'Java 17 is required' >&2; exit 1; }
[[ $(mvn -version | head -1) == *'3.9.16'* ]] || { echo 'Reviewed Maven version 3.9.16 is required' >&2; exit 1; }

cache="$project_root/.upstream/$commit"
mkdir -p "$cache"
build_dir=$(mktemp -d "$cache/build.XXXXXX")
repository="$cache/repository"
git -C "$source_repo" archive "$commit" | tar -x -C "$build_dir"
timestamp=$(git -C "$source_repo" show -s --format=%cI "$commit")

# No samples, Spring Boot apps, frontend installs, models, or upstream shell scripts.
# Upstream coverage thresholds are not the artifact-build gate. Tests are NOT skipped.
mvn ${offline:+"$offline"} -B -ntp -f "$build_dir/pom.xml" -pl open-agent-auth-core -am \
    "-Dmaven.repo.local=$repository" "-Dproject.build.outputTimestamp=$timestamp" \
    -Djacoco.skip=true -DargLine= install

jar="$repository/com/alibaba/openagentauth/open-agent-auth-core/$version/open-agent-auth-core-$version.jar"
jar_hash=$(shasum -a 256 "$jar" | cut -d ' ' -f 1)
[[ "$jar_hash" == $(jq -er '.coreJarSha256' "$lock") ]] || { echo 'Upstream JAR differs from reviewed hash' >&2; exit 1; }
jq -n --arg commit "$commit" --arg version "$version" --arg sha256 "$jar_hash" \
    --arg timestamp "$timestamp" --arg buildDirectory "$build_dir" \
    '{commit:$commit,artifactVersion:$version,sha256:$sha256,outputTimestamp:$timestamp,buildDirectory:$buildDirectory}' \
    > "$cache/build-receipt.json"
echo "Pinned core ready: $jar"
echo "SHA-256: $jar_hash"
