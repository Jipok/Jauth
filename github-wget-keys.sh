#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

search() {
        q=$( echo $@ | tr " " '+' )
        curl -s "https://github.com/search?q=$q&ref=opensearch&type=users" |\
                jq -r '.payload.results.[] | .login + " {" + .name + "}"' |\
                sed 's/{}//g'
}
export -f search

username=$(echo "" | fzf --bind "change:reload-sync:search {q}" | cut -f1 -d' ')
filename=${username}.keys
wget "https://github.com/$filename"

sed -i "s/\$/ $username/" $filename

if [[ ! -s $filename ]]; then
        echo -e "\033[0;31mUser has no keys \033[0m"
        rm $filename
        exit 0
fi

echo -e "\033[0;32mSaved to file $filename: \033[0m"
cat $filename
