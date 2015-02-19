# iptconf package installation
class iptconf2::install {
  include iptconf2::params
  include $iptconf2::params::iptconf2_repo
  Package {
    require => Class[$iptconf2::params::iptconf2_repo],
  }
}
# vim:set et:
# vim:set sts=2 ts=2:
# vim:set shiftwidth=2:
