%if 0%{?suse_version}
%define    init   init.d
%else # fedora
%define    init   rc.d/init.d
%endif

Name:             iptconf
Version:          1.2.1
Release:          1%{?dist}
Summary:          Iptables configuration

Group:            Productivity/Networking/Security
License:          GPL-2.0
URL:              https://github.com/stefjakobs/iptconf
Source0:          %{name}-%{version}.tar.gz
BuildRoot:        %{_tmppath}/%{name}-%{version}-build
BuildArch:        noarch

BuildRequires:    filesystem
%if 0%{?suse_version}
Requires(pre):    %fillup_prereq %insserv_prereq
%else # fedora
Requires(post):   chkconfig
Requires(preun):  chkconfig initscripts
%endif

Requires:         bash
Requires:         iptables
Requires:         logrotate
Conflicts:        SuSEfirewall2


%description
iptconf is a bash script which sets the firewall while starting a network
interface. Its syntax is similar to iptables.

%prep
%setup -q


%build


%install
# install into /usr/sbin
install -Dm755 %{name} %{buildroot}/%{_sbindir}/%{name}
install -Dm644 %{name}.f %{buildroot}/%{_usr}/lib/%{name}/%{name}.f
install -Dm644 ipt.conf %{buildroot}/%{_sysconfdir}/ipt.conf
install -Dm644 %{name}.8 %{buildroot}/%{_mandir}/man8/%{name}.8
install -Dm755 %{name}.if-up %{buildroot}/%{_sysconfdir}/sysconfig/network/if-up.d/iptconf
install -Dm644 %{name}.logrotate %{buildroot}/%{_sysconfdir}/logrotate.d/%{name}
# install init scripts
install -Dm755 %{name}.init $RPM_BUILD_ROOT/%{_sysconfdir}/%{init}/%{name}
%if 0%{?suse_version}
install -d -m755 $RPM_BUILD_ROOT/%{_sbindir}
ln -sf %{_sysconfdir}/%{init}/%{name} $RPM_BUILD_ROOT/%{_sbindir}/rc%{name}
%endif
# create config dir
install -d -m755 $RPM_BUILD_ROOT/%{_sysconfdir}/ipt.conf.d


%clean
%__rm -rf "%{buildroot}"


%post
%if 0%{?suse_version}
  %{fillup_and_insserv -y %{name}}
%else # fedora
  %if 0%{?fedora_version} > 15
    if [ $1 -eq 1 ] ; then # Initial installation 
      /bin/systemctl daemon-reload >/dev/null 2>&1 || :
    fi
  %else
    /sbin/chkconfig --add %{name}
  %endif
%endif

%preun
%if 0%{?suse_version}
  %stop_on_removal %{name}
%else # fedora
  if [ $1 -eq 0 ] ; then
    %if 0%{?fedora_version} > 15
      /bin/systemctl stop %{name}.service > /dev/null 2>&1 || :
      /bin/systemctl --no-reload disable %{name}.service > /dev/null 2>&1 || :
    %else
      /sbin/service %{name} stop >/dev/null 2>&1
      /sbin/chkconfig --del %{name}
    %endif
  fi
%endif

%postun
%if 0%{?suse_version}
  %restart_on_update %{name}
  %insserv_cleanup
%else # fedora
  %if 0%{?fedora_version} > 15
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
    if [ $1 -ge 1 ] ; then # Package upgrade, not uninstall
      /bin/systemctl try-restart %{name}.service >/dev/null 2>&1 || :
    fi
  %else
    if [ $1 -ge 1 ] ; then
      /sbin/service %{name} condrestart >/dev/null 2>&1 || :
    fi
  %endif
%endif


%files
%defattr(-,root,root,-)
%config /etc/%{init}/%{name}
%if 0%{?suse_version}
%{_sbindir}/rc%{name}
%endif
%{_sbindir}/*
%dir %{_usr}/lib/%{name}
%{_usr}/lib/%{name}/%{name}.f
%config(noreplace) %{_sysconfdir}/ipt.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%dir %{_sysconfdir}/ipt.conf.d
%{_sysconfdir}/sysconfig/network/if-up.d/%{name}
%doc %{_mandir}/man8/%{name}.8*


%changelog
* Mon Apr 28 2014 Stefan Jakobs <projects AT localside.net> - 1.2.1
- rework of sysVinit script: iptconf (while stopping disable ipv6, too)
* Fri Dec 13 2013 Stefan Jakobs <projects AT localside.net> - 1.2
- mv iptconf.f into /usr/lib/iptconf/
* Mon Apr 08 2013 Stefan Jakobs <projects AT localside.net> - 1.1
- add /etc/ipt.conf.d/ for custom rules
* Fri Nov 23 2012 Stefan Jakobs <projects AT localside.net> - 1.0
- Initial version
