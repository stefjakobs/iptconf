# define iptconf rules
# install a file with the rules name
define iptconf2::rules {
  include iptconf2

  file { $name:
    owner   => 'root',
    group   => 'root',
    mode    => '0440',
    path    => "/etc/ipt.conf.d/${name}.conf",
    source  => "puppet:///modules/iptconf2/${name}",
    require => Class['iptconf2::install'],
    notify  => Class['iptconf2::service'],
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
