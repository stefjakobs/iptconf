define iptconf2::rule (
  $chain          = 'INPUT',
  $description    = undef,
  $prio           = '00',
  $sources        = undef,
  $dests          = undef,
  $protos         = 'tcp',
  $sports         = undef,
  $dports         = undef,
  $target         = 'ACCEPT',
  $args           = '',
  $notarule       = false,
  $limit_hitcount = '0',
  $limit_interval = '60',
  $template       = 'iptconf-rule'
) {

  include iptconf2::install
  include iptconf2::service

  validate_string($chain)
  validate_string($description)
  validate_string($prio)
  validate_string($target)
  validate_string($args)
  validate_string($template)

  $srcarray   = any2array($sources)
  $dstarray   = any2array($dests)
  $protoarray = any2array($protos)
  $sportarray = any2array($sports)
  $dportarray = any2array($dports)

  if $protoarray == [ 'all' ] {
    $used_protos = []
  } else {
    $used_protos = $protoarray
  }
  # FIXME: add dests into template and use more ruby magic to assemble line...
  file {
    "/etc/ipt.conf.d/${prio}_${name}.conf":
      ensure  => present,
      mode    => '0400',
      content => template("iptconf2/${template}.erb"),
      require => Class['iptconf2::install'],
      notify  => Class['iptconf2::service'],
  }
}

# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
