#!/usr/bin/env bash
# Prints the next release version (no "v") from the Conventional Commit
# messages since the last vX.Y.Z tag, or nothing if none warrants a release:
#
#	type!: …  or a "BREAKING CHANGE:" footer   major
#	feat: …                                     minor
#	fix: …  or  perf: …                         patch
#
# Other types (chore, ci, docs, refactor, test, …) and non-conventional
# messages don't release. With no tag yet, the first release is 0.1.0.
set -euo pipefail

# Highest plain vX.Y.Z tag reachable from HEAD (pre-release tags are ignored).
last=$(git tag --merged HEAD --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)
if [[ -z $last ]]; then
	echo 0.1.0
	exit 0
fi

scope='(\([^)]*\))?'
breaking="^[a-z]+${scope}!:"
feat="^feat${scope}:"
fix="^(fix|perf)${scope}:"

bump=
while IFS= read -r -d '' msg; do
	subject=${msg%%$'\n'*}
	if [[ $subject =~ $breaking ]] || grep -qE '^BREAKING[ -]CHANGE: ' <<<"$msg"; then
		bump=major
		break
	elif [[ $subject =~ $feat ]]; then
		bump=minor
	elif [[ $subject =~ $fix && -z $bump ]]; then
		bump=patch
	fi
done < <(git log -z --format=%B "$last..HEAD")

IFS=. read -r major minor patch <<<"${last#v}"
case $bump in
major) echo "$((major + 1)).0.0" ;;
minor) echo "$major.$((minor + 1)).0" ;;
patch) echo "$major.$minor.$((patch + 1))" ;;
esac
