#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# filter.py - extract OpenWebNet frames from a tcpdump -A text stream.
#
# tcpdump -A prints packet payloads as text; OpenWebNet frames look like
# "*...##". A single tcpdump line can contain several coalesced frames
# (e.g. "*1##*2##") plus header noise, so emit EACH complete "*...##" frame on
# its own line. StartMqttSend pipes this to `mosquitto_pub -l`, which publishes
# one MQTT message per line, so each frame becomes its own message.
#
# Reimplements the behaviour of fquinto's mqtt_scripts/filter.py (GPL-2.0) as an
# independent MIT-licensed script for IntercomFirmwareTool. Python 2 and 3.
from __future__ import print_function

import re
import sys

# A frame starts at '*' and ends at the first '##' terminator. Non-greedy so
# concatenated frames on one line are split; internal '*' bytes stay in-frame.
FRAME = re.compile(r"\*.*?##")

# Session ACK/NACK control frames carry no bus event. Drop them so the tcpdump
# back-end matches the socket framer (frame_own), which also drops them — this
# keeps both raw and JSON payloads consistent across the two capture back-ends.
CONTROL = frozenset(("*#*1##", "*#*0##"))


def main():
    # iter(readline, "") instead of "for line in sys.stdin": on CPython 2 the
    # latter uses an internal read-ahead buffer that withholds lines on a pipe,
    # which would defeat the low-latency (line-buffered) goal. readline is prompt
    # on both Python 2 and 3.
    for line in iter(sys.stdin.readline, ""):
        for match in FRAME.finditer(line):
            frame = match.group(0)
            if frame in CONTROL:
                continue
            print(frame)
            sys.stdout.flush()


if __name__ == "__main__":
    main()
