# iptconf configuration files
class iptconf2::loadfast {

  include iptconf2::install

  File {
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => 0440,
    require => Class['iptconf2::install'],
    notify  => Class['iptconf2::service'],
  }

  file {
    '/etc/default/iptconf':
      source  => 'puppet:///modules/iptconf2/iptconf.loadfast';

    '/etc/default/iptconf.dpkg-dist':
      ensure  => absent;

    '/etc/default/iptconf.dpkg-old':
      ensure  => absent;
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
