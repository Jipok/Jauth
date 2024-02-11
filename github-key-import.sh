#!/usr/bin/env bash
set -euo pipefail

file="${1:-$HOME/authorized_keys}"

search() {
        q=$( echo $@ | tr " " '+' )
        curl -s "https://github.com/search?q=$q&ref=opensearch&type=users" |\
                jq -r '.payload.results.[] | .login + " {" + .name + "}"' |\
                sed 's/{}//g'
}
export -f search

username=$(echo "" | fzf --bind "change:reload-sync:search {q}" | cut -f1 -d' ')
keys=$(curl -s "https://github.com/$username.keys" | sed "s/\$/ $username/")

echo "Public keys: $keys"
echo "Username: $username"
[ -z "$@" ] && echo -e "\e[0;33mFilename not provided via cmdline. Using default one:\e[m"
echo "Append to: $file"

read -r -p "Are you sure? [Y/n]" response
response=${response,,} # tolower
if [[ $response =~ ^(y| ) ]] || [[ -z $response ]]; then
        echo "$keys" >> "$file"
        echo "DONE"
else
        echo "CANCELED"
fi
