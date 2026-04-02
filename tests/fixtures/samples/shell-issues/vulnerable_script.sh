#!/bin/bash
# shellcheck disable=all
# Sample shell script with INTENTIONAL issues for testing
# These issues will be detected by ShellCheck
#
# DO NOT use this script in production - it exists only for testing

# SC2086: Double quote to prevent globbing and word splitting
filename=$1
cat $filename

# SC2006: Use $(...) instead of backticks
date=$(date +%Y-%m-%d)
echo "Today is $date"

# SC2046: Quote this to prevent word splitting
files=$(find . -name "*.txt")
rm $files

# SC2001: See if you can use ${var//search/replace} instead
cleaned=$(echo "$filename" | sed 's/foo/bar/g')

# SC2012: Use find instead of ls to better handle non-alphanumeric filenames
for file in $(ls *.log); do
  echo "Processing $file"
done

# SC2068: Double quote array expansions to avoid re-splitting elements
args=("$@")
command ${args[@]}

# SC2034: Variable appears unused
unused_var="this is never used"

# SC2004: $/${} is unnecessary on arithmetic variables
count=5
result=$((count + 1))

# SC2162: read without -r will mangle backslashes
read input_value
echo "You entered: $input_value"

# SC2115: Use "${var:?}" to ensure this never expands to /* (dangerous rm)
dir=""
rm -rf $dir/*

# SC2155: Declare and assign separately to avoid masking return values
export PATH=$(get_custom_path)

# SC2009: Consider using pgrep instead of grepping ps output
running_processes=$(ps aux | grep "myapp")
echo "$running_processes"

# SC2027: The surrounding quotes actually break this
echo "The path is: "$HOME"/myapp"

# SC2028: echo won't expand escape sequences; use printf
echo "Line1\nLine2"

get_custom_path() {
  echo "/usr/local/bin"
}
