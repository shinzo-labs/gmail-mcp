#! /bin/sh

BASE_BRANCH=${GITHUB_BASE_REF:-main}
git fetch origin $BASE_BRANCH

pkg_version=$(jq -r .version package.json)
base_version=$(git show origin/$BASE_BRANCH:package.json | jq -r .version)

# Check if version has changed from base branch
if [ "$pkg_version" != "$base_version" ]; then
  echo "Error: Version should not change from base branch."
  echo "Base branch version: $base_version"
  echo "PR version: $pkg_version"
  exit 1
fi

# Check if package version matches the version in FILE_PATH
if [ -n "$FILE_PATH" ] && [ -f "$FILE_PATH" ]; then
  file_content=$(cat "$FILE_PATH")
  file_version=$(echo "$file_content" | grep -o 'version: "[0-9]\+\.[0-9]\+\.[0-9]\+"' | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
  
  if [ "$pkg_version" != "$file_version" ]; then
    echo "Error: Version in package.json ($pkg_version) does not match version in $FILE_PATH ($file_version)"
    exit 1
  fi
else
  echo "Warning: FILE_PATH not set or file does not exist. Skipping file version check."
  exit 1
fi

echo "Version validation passed: $pkg_version"
