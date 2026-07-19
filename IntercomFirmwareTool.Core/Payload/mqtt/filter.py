#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# filter.py - extract OpenWebNet frames from a tcpdump -A text stream.
#
# tcpdump -A prints packet payloads as text; OpenWebNet frames look like
# "*...##". For each line that contains a frame terminator "##", emit the text
# from the first "*" onward so only the frame (not tcpdump's header noise) is
# published. Line-buffered so frames reach MQTT with minimal latency.
#
# Reimplements the behaviour of fquinto's mqtt_scripts/filter.py (GPL-2.0) as an
# independent MIT-licensed script for IntercomFirmwareTool. Python 2 and 3.
from __future__ import print_function

import sys


def main():
    for line in sys.stdin:
        if "##" not in line:
            continue
        start = line.find("*")
        if start < 0:
            continue
        print(line[start:], end="")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
