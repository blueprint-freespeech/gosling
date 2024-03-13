#!/usr/bin/env bash

# Check if three arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 crate version"
    exit 1
fi

# Assign arguments to variables
crate=$1
version=$2

# Check if the crate name is valid
valid_crates=("honk-rpc" "tor-interface" "gosling" "cgosling")
if ! [[ " ${valid_crates[@]} " =~ " $crate " ]]; then
    echo "Invalid crate name. Valid crate names are: ${valid_crates[*]}"
    exit 1
fi

# Validate semantic version format
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version format. Please provide semantic version (e.g., 1.2.3)"
    exit 1
fi

# Sign and tag the current git HEAD
tag_name="${crate}-v${version}"
commit_message="signing ${crate} version ${version}"

echo "Signing and tagging with tag name: ${tag_name}"
git tag -s "$tag_name" -m "$commit_message"
