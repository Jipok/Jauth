#!/usr/bin/env bash
set -euo pipefail

file="${1:-$HOME/.ssh/authorized_keys}" 

search() {
	q=$( echo $@ | tr " " '+' )
	curl -s "https://github.com/search?q=$q&ref=opensearch&type=users" |\
        	jq -r '.payload.results.[] | .login + " {" + .name + "}"' |\
		sed 's/{}//g'
}
export -f search

username=$(echo "" | fzf --bind "change:reload-sync:search {q}" | cut -f1 -d' ')
key=$(curl -s "https://github.com/$username.keys" | head -n1)

echo "Public key: $key"
echo "Username: $username"
[ -z "$@" ] && echo "Filename not provided via cmdline. Using default one:"
echo "Append to: $file"

read -r -p "Are you sure? [Y/n]" response
response=${response,,} # tolower
if [[ $response =~ ^(y| ) ]] || [[ -z $response ]]; then
	echo "$key $username" >> "$file"
fi
