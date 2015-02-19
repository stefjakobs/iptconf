# everything, that is needed to have execute iptconf
class iptconf2 {
  include iptconf2::install, iptconf2::config, iptconf2::service
  include iptconf2::defaults

  ## realize all virtual resources
  Iptconf2::Rule <||>
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
