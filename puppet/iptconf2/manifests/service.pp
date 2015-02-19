# define an iptconf service
class iptconf2::service {
  include iptconf2::config

  exec { '/usr/sbin/iptconf':
    refreshonly => true,
    subscribe   => File['/etc/ipt.conf'],
    require     => Class['iptconf2::config'],
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
