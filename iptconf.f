# iptconf functions

# iptables chain INPUT ipv4+ipv6
INPUT() { ip46tables -A INPUT "$@"; }

# iptables chain OUTPUT ipv4+ipv6
OUTPUT() { ip46tables -A OUTPUT "$@"; }

# iptables chain FORWARD ipv4+ipv6
FORWARD() { ip46tables -A FORWARD "$@"; }

# iptables chain PREROUTING ipv4+ipv6
PREROUTING() { ip46tables -A PREROUTING "$@"; }

# iptables chain INPUT ipv4
INPUT4() { vx iptables -A INPUT "$@"; }

# iptables chain OUTPUT ipv4
OUTPUT4() { vx iptables -A OUTPUT "$@"; }

# iptables chain FORWARD ipv4
FORWARD4() { vx iptables -A FORWARD "$@"; }

# iptables chain FORWARD ipv4
PREROUTING4() { vx iptables -A PREROUTING "$@"; }

# iptables chain INPUT ipv6
INPUT6() { vx ip6tables -A INPUT "$@"; }

# iptables chain OUTPUT ipv6
OUTPUT6() { vx ip6tables -A OUTPUT "$@"; }

# iptables chain FORWARD ipv6
FORWARD6() { vx ip6tables -A FORWARD "$@"; }

# iptables chain FORWARD ipv6
PREROUTING6() { vx ip6tables -A PREROUTING "$@"; }

# iptables ipv4+ipv6
ip46tables() {
  if [[ "$*" =~ " -s " || "$*" =~ "--source" || \
        "$*" =~ " -d " || "$*" =~ "--destination" ]]; then
    if ip4test "$@"; then
      vx iptables "$@"
    fi
    if ip6test "$@"; then
      vx ip6tables "$@"
      return
    fi
  else
    vx iptables "$@"
    vx ip6tables "$@"
  fi
}

ip4test() {
  while [ "$1" ]; do
    if [ x"$1" = x-s -o x"$1" = x-d ]; then
      shift
      [[ "$1" =~ ^[0-9./]+$ || $(host -t a $1) =~ "has address" ]] && return 0
    fi
    shift
  done
  return 1
}

ip6test() {
  while [ -n "$1" ]; do
    if [ x"$1" = x-s -o x"$1" = x-d ]; then
      shift
      [[ "$1" =~ ^[0-9a-fA-F:/]+$ || $(host -t aaaa $1) =~ "has IPv6 address" ]] && return 0
    fi
    shift
  done
  return 1
}

# verbose execution
vx() {
  verbose "$@"
  "$@" || exit $?
}

verbose() {
  test $verbose && echo "$@"
}

warn() { echo "$@" >&2; }

verbose=
[ x"$1" = x-v ] && verbose=v

# ensure a defined return
true

