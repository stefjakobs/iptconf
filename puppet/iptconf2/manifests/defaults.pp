# Default rules that are generated for ALL hosts
class iptconf2::defaults {
  @iptconf2::rule {
    'workstations':
      prio    => '001',
      sources => ['192.168.11.0/27'],
      protos  => ['all'],
      chain   => 'INPUT4';
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
