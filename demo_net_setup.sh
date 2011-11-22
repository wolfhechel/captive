#!/bin/sh

if [ $UID -gt 0 ]; then
    sudo `cd ${0%/*}; pwd`/${0##*/}
    vboxmanage startvm ArchLinux --type headless 2>/dev/null
    while true; do
        if ssh 192.168.3.2 2>/dev/null; then
            break
        fi
    done
exit; fi

check_bridge() {
    if brctl show | grep br0 > /dev/null 2> /dev/null; then
	return 0
    else
	return 1
    fi
}

if check_bridge; then exit; fi

brctl addbr br0

ip -b - << EOF
tuntap add dev tap0 mode tap group users
addr add dev br0 192.168.0.1/24
addr add dev tap0 0.0.0.0
link set br0 up
link set tap0 up
EOF

brctl addif br0 tap0
