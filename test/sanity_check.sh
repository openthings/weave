#! /bin/bash

. "$(dirname "$0")/config.sh"

set -e

whitely echo Ping each host from the other

for host in $HOSTS; do
    for other in $HOSTS; do
        if [ "$host" != "$other" ]; then
            echo $(run_on $host $PING $other) &
            pids="$pids $!"
        fi
    done
done
for pid in $pids; do wait $pid; done
unset pids


whitely echo Check we can reach docker

function check_docker() {
    docker_version=$(docker_on $1 version)
    docker_info=$(docker_on $1 info)
    docker_weave_version=$(docker inspect -f {{.Created}} weaveworks/weave:${WEAVE_VERSION:-latest})
    weave_version=$(weave_on $1 version)
    cat << EOF

Host Version Info: $1
=====================================
# docker version
$docker_version
# docker info
$docker_info
# weave version
$docker_weave_version
$weave_version
EOF
}

for host in $HOSTS; do
    check_docker $host &
    pids="$pids $!"
done
for pid in $pids; do wait $pid; done
