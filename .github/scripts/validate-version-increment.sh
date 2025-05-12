#! /bin/sh

BASE_BRANCH=${GITHUB_BASE_REF:-main}
git fetch origin $BASE_BRANCH

pkg_version=$(jq -r .version package.json)
base_version=$(git show origin/$BASE_BRANCH:package.json | jq -r .version)

IFS='.' read -r pkg_major pkg_minor pkg_patch <<< "$pkg_version"
IFS='.' read -r base_major base_minor base_patch <<< "$base_version"

inc_count=0

if [ "$pkg_major" -eq $((base_major + 1)) ] && [ "$pkg_minor" -eq 0 ] && [ "$pkg_patch" -eq 0 ]; then
  inc_count=1
elif [ "$pkg_major" -eq "$base_major" ] && [ "$pkg_minor" -eq $((base_minor + 1)) ] && [ "$pkg_patch" -eq 0 ]; then
  inc_count=1
elif [ "$pkg_major" -eq "$base_major" ] && [ "$pkg_minor" -eq "$base_minor" ] && [ "$pkg_patch" -eq $((base_patch + 1)) ]; then
  inc_count=1
fi

if [ "$inc_count" -ne 1 ]; then
  echo "Error: Version must increment one of major, minor, or patch by 1 (and reset lower segments if major/minor is incremented)."
  echo "Base branch version: $base_version"
  echo "PR version: $pkg_version"
  exit 1
fi
