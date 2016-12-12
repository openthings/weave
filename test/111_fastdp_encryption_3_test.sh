#!/bin/bash

. ./config.sh

C1=10.2.1.4
C2=10.2.1.7

start_suite "Ping over encrypted cross-host weave network (fastdp)"

weave_on $HOST1 launch --password wfvAwt7sj
weave_on $HOST2 launch --password wfvAwt7sj $HOST1
weave_on $HOST3 launch --password wfvAwt7sj $HOST1

assert_raises "weave_on $HOST1 status connections | grep -P 'encrypted *fastdp'"
assert_raises "weave_on $HOST2 status connections | grep -P 'encrypted *fastdp'"

PCAP=$(mktemp)
echo $PCAP

$SSH $HOST2 "sudo nohup tcpdump -i any -w $PCAP >/dev/null 2>&1 & echo \$! > $PCAP.pid"

start_container $HOST1 $C1/24 --name=c1
start_container $HOST2 $C2/24 --name=c2
assert_raises "exec_on $HOST1 c1 $PING $C2"

$SSH $HOST2 "sudo kill \$(cat $PCAP.pid) && rm -f $PCAP.pid"
$SSH $HOST2 "sudo base64 $PCAP" | base64 -d > $PCAP

# All vxlan tunneled traffic goes over ESP
assert "tcpdump -r $PCAP 'src host1 && dst host2 && dst port 6784'" ""
assert "tcpdump -r $PCAP 'src host2 && dst host1 && dst port 6784'" ""
# 50 proto is for ESP
assert_raises "[[ -n $(tcpdump -r $PCAP 'src host1 && dst host2 && proto 50') ]]"
assert_raises "[[ -n $(tcpdump -r $PCAP 'src host2 && dst host1 && proto 50') ]]"

# TODO:
# - check SPI
# - check reset

end_suite
