# iptconf configuration files
class iptconf2::config {

  File {
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0440',
    require => Class['iptconf2::install'],
    notify  => Class['iptconf2::service'],
  }

  include iptconf2::defaults

  file {
    '/etc/ipt.conf.d':
      ensure  => directory,
      recurse => true,
      purge   => true,
      mode    => '0750';

    '/etc/ipt.conf.d/AAA_MANAGED_BY_PUPPET':
      ensure  => present,
      content => '';

    '/etc/ipt.conf':
      source  => 'puppet:///modules/iptconf2/ipt.conf';

    '/etc/ipt.conf.d/999-policies.conf':
      source => 'puppet:///modules/iptconf2/999-policies.conf';

    '/etc/ipt.ulli':
      ensure  => absent;

    '/etc/ipt.conf.rpmnew':
      ensure  => absent;

    '/etc/ipt.conf.dpkg-old':
      ensure  => absent;

    '/root/bin/iptconf':
      ensure  => absent;

    '/root/bin/iptconf.f':
      ensure  => absent;
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
