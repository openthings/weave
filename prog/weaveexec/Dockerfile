#FROM aarch64/alpine:edge

FROM openthings/ubuntu-rock:ARM64

MAINTAINER Weaveworks Inc <help@weave.works>
LABEL works.weave.role=system

WORKDIR /home/weave
ENTRYPOINT ["/home/weave/sigproxy", "/home/weave/weave"]

#RUN apk add --update \
#    bash curl ethtool iptables iproute2 libltdl7-dev\
#    util-linux conntrack-tools bind-tools \
#    && rm -rf /var/cache/apk/*

RUN apt-get update && apt-get install -y \
    apt-utils curl ethtool iptables iproute2 \
    util-linux bison libc6 libltdl7-dev libnetfilter-conntrack3
# bison flex libnfnetlink-dev libmnl-dev
##    conntrack-tools \
##    bind-tools \
##    && apt-get autoremove
##  && rm -rf /var/cache/apk/*


ADD ./weave ./sigproxy ./weaveproxy ./symlink /home/weave/
ADD ./weaveutil /usr/bin/
ADD ./weavewait /w/w
ADD ./weavewait_noop /w-noop/w
ADD ./weavewait_nomcast /w-nomcast/w

#ADD ./docker.tgz /
ADD ./docker /usr/local/bin

#ENTRYPOINT ["/bin/bash"]
