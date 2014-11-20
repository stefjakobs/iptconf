#!/bin/sh

VERSION=1.2.1

txt2man -t spread -r "iptables configuration" -v $VERSION -s 8 < iptconf.8.txt > iptconf-$VERSION/iptconf.8

