## iptconf2 parameters
class iptconf2::params {
  case $::operatingsystem {
    /(opensuse|SLES)/: {
      $iptconf2_package = 'iptconf'
      $iptconf2_repo    = 'repos::iptconf'
    }
    /(Ubuntu|Debian)/: {
      $iptconf2_package = 'iptconf'
      $iptconf2_repo    = 'repos::iptconf'
    }
    default: {
      fail("Module ${module_name} is not supported on ${::operatingsystem}")
    }
  }
}
