# 
#

.PHONY: help usage all

help: usage

usage:
	@echo "      iptconf $(VERSION), You can do :"
	@echo "make install # as root"
	echo ""

PREFIX ?= /usr

VERSION=$(shell ./iptconf --version)

install: manpages
	install -D -m0755 iptconf $(DESTDIR)$(PREFIX)/sbin/iptconf
	install -D -m0755 iptconfparser $(DESTDIR)$(PREFIX)/sbin/iptconfparser
	install -D -m0755 iptconf-wrapper $(DESTDIR)$(PREFIX)/sbin/iptconf-wrapper
	install -D -m0644 iptconf.f $(DESTDIR)$(PREFIX)/lib/iptconf.f
	install -D -m0644 share/iptconf.footer $(DESTDIR)$(PREFIX)/share/iptconf/iptconf.footer
	install -D -m0644 share/iptconf.header $(DESTDIR)$(PREFIX)/share/iptconf/iptconf.header
	install -D -m0644 share/iptconf.reset $(DESTDIR)$(PREFIX)/share/iptconf/iptconf.reset
	install -D -m0644 iptconf.default $(DESTDIR)/etc/default/iptconf
	install -D -m0644 ipt.conf $(DESTDIR)/etc/ipt.conf
	install -d -m 0755 $(DESTDIR)/etc/ipt.conf.d
	install -D -m0644 perl5/IptConf/IptConf.pm $(DESTDIR)/share/perl5/IptConf/IptConf.pm
	install -D -m0644 perl5/IptConf/IptablesParser.pm $(DESTDIR)/share/perl5/IptConf/IptablesParser.pm
	install -D -m0644 perl5/IptConf/DebugLib.pm $(DESTDIR)/share/perl5/IptConf/DebugLib.pm
	install -D -m0644 perl5/IptConf/NetworkLib.pm $(DESTDIR)/share/perl5/IptConf/NetworkLib.pm

manpages:
	txt2man -t spread -r "iptables configuration" -v $(VERSION) -s 8 < iptconf.8.txt > $(DESTDIR)$(PREFIX)/share/man/man8/iptconf.8
