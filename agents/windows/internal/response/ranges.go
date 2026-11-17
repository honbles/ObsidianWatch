package response

import (
	"math/big"
	"net/netip"
	"sort"
)

// ival is an inclusive address interval.
type ival struct{ lo, hi *big.Int }

func addrInt(a netip.Addr) *big.Int { return new(big.Int).SetBytes(a.AsSlice()) }

func intAddr(n *big.Int, v6 bool) netip.Addr {
	size := 4
	if v6 {
		size = 16
	}
	a, _ := netip.AddrFromSlice(n.FillBytes(make([]byte, size)))
	return a
}

func prefixIval(p netip.Prefix) ival {
	p = p.Masked()
	lo := addrInt(p.Addr())
	bits := p.Addr().BitLen()
	span := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
	hi := new(big.Int).Sub(new(big.Int).Add(lo, span), big.NewInt(1))
	return ival{lo, hi}
}

func ipIval(a netip.Addr) ival { n := addrInt(a); return ival{n, new(big.Int).Set(n)} }

// complementRanges returns the address ranges ("a-b" or a single address) that
// cover the whole IPv4 or IPv6 space EXCEPT the keep intervals. It is how a
// Windows Firewall "block everything but the backend" rule is expressed, since
// block rules override allow rules there.
func complementRanges(keep []ival, v6 bool) []string {
	bits := 32
	if v6 {
		bits = 128
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	sort.Slice(keep, func(i, j int) bool { return keep[i].lo.Cmp(keep[j].lo) < 0 })
	var merged []ival
	for _, k := range keep {
		if n := len(merged); n > 0 {
			next := new(big.Int).Add(merged[n-1].hi, big.NewInt(1))
			if k.lo.Cmp(next) <= 0 {
				if k.hi.Cmp(merged[n-1].hi) > 0 {
					merged[n-1].hi = k.hi
				}
				continue
			}
		}
		merged = append(merged, ival{new(big.Int).Set(k.lo), new(big.Int).Set(k.hi)})
	}
	var out []string
	emit := func(lo, hi *big.Int) {
		if lo.Cmp(hi) > 0 {
			return
		}
		if lo.Cmp(hi) == 0 {
			out = append(out, intAddr(lo, v6).String())
			return
		}
		out = append(out, intAddr(lo, v6).String()+"-"+intAddr(hi, v6).String())
	}
	cur := big.NewInt(0)
	for _, k := range merged {
		if k.lo.Cmp(cur) > 0 {
			emit(cur, new(big.Int).Sub(k.lo, big.NewInt(1)))
		}
		cur = new(big.Int).Add(k.hi, big.NewInt(1))
	}
	if cur.Cmp(max) <= 0 {
		emit(cur, max)
	}
	return out
}

// blockRanges returns the v4+v6 ranges a platform firewall should BLOCK so
// that only allow (plus loopback and, optionally, link-local control
// traffic) stays reachable.
func blockRanges(allow []netip.Addr, linkLocalV6 bool) []string {
	var k4, k6 []ival
	k4 = append(k4,
		prefixIval(netip.MustParsePrefix("127.0.0.0/8")),
		ipIval(netip.MustParseAddr("0.0.0.0")),
		ipIval(netip.MustParseAddr("255.255.255.255")))
	k6 = append(k6, ipIval(netip.MustParseAddr("::1")))
	if linkLocalV6 {
		k6 = append(k6, prefixIval(netip.MustParsePrefix("fe80::/10")), prefixIval(netip.MustParsePrefix("ff00::/8")))
	}
	for _, a := range allow {
		if a.Is4() {
			k4 = append(k4, ipIval(a))
		} else {
			k6 = append(k6, ipIval(a))
		}
	}
	return append(complementRanges(k4, false), complementRanges(k6, true)...)
}
