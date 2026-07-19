#!/bin/sh
# TcpDump2Mqtt.sh - init launcher for the MQTT bridge (symlinked from rc5.d).
#
# Starts the TcpDump2Mqtt orchestrator once, in the background. Guards against
# duplicate instances if the init system runs this more than once.
#
# MIT-licensed reimplementation of fquinto's mqtt_scripts/TcpDump2Mqtt.sh
# (GPL-2.0) for IntercomFirmwareTool.
PATH=/sbin:/usr/sbin:/usr/bin:/bin

if /usr/bin/pgrep -f "/etc/tcpdump2mqtt/TcpDump2Mqtt$" > /dev/null 2>&1; then
	echo "TcpDump2Mqtt already running, skipping"
	exit 0
fi

/etc/tcpdump2mqtt/TcpDump2Mqtt > /tmp/tcp_log.txt 2>&1 &
exit 0
