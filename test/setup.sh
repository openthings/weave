#!/bin/bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

. ./config.sh

(cd ./tls && ./tls $HOSTS)

echo "Copying weave images, scripts, and certificates to hosts, and"
echo "  prefetch test images"

setup_host() {
    HOST=$1
    docker_on $HOST load -i ../weave.tar.gz &
    local pids="$!"
    
    DANGLING_IMAGES="$(docker_on $HOST images -q -f dangling=true)"
    [ -n "$DANGLING_IMAGES" ] && docker_on $HOST rmi $DANGLING_IMAGES 1>/dev/null 2>&1 || true
    run_on $HOST mkdir -p bin
    
    upload_executable $HOST ../bin/docker-ns &
    local pids="$pids $!"
    
    upload_executable $HOST ../weave &
    local pids="$pids $!"

    rsync -az -e "$SSH" --exclude=tls ./tls/ $HOST:~/tls &
    local pids="$pids $!"

    for IMG in $TEST_IMAGES ; do
        docker_on $HOST inspect --format=" " $IMG >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Pulling $IMG on $HOST..."
            docker_on $HOST pull $IMG >/dev/null 2>&1 &
            local pids="$pids $!"
        fi
    done
    for pid in $pids; do wait $pid; done
}

for HOST in $HOSTS; do
    setup_host $HOST &
    ppids="$ppids $!"
done

# Wait individually for tasks so we fail-exit on any non-zero return code
# ('wait' on its own always returns 0)
for pid in $ppids; do
    wait $pid;
done
