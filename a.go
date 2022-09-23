package spf

import (
	"fmt"
	"net"
)

type A struct {
	Qualifier Qualifier
	Record    string
	Domain    string
	CIDR4     string
	CIDR6     string
	r         resolver
	Networks  []*net.IPNet
}

func (a A) Match(ip net.IP) (m []string, errRtn error) {
	for _, v := range a.Networks {
		if v.Contains(ip) {
			m = []string{a.Record}
			return
		}
	}
	return
}

func extractArecordIPs(res resolver, domain string, cidr4 string, cidr6 string) (ListOfNetworks []*net.IPNet, errRtn error) {
	ips, err := res.ARecord(domain)
	if err != nil {
		errRtn = fmt.Errorf("%w - %s", DNSResolutionError, err)
		return
	}
	if cidr4 == "" {
		cidr4 = "32"
	}
	if cidr6 == "" {
		cidr6 = "128"
	}
	for _, v := range ips {
		var ipRange string
		if v.To4() != nil {
			ipRange = fmt.Sprintf("%s/%s", v.String(), cidr4)
		} else {
			ipRange = fmt.Sprintf("%s/%s", v.String(), cidr6)
		}
		_, r, err := net.ParseCIDR(ipRange)
		if err != nil {
			errRtn = fmt.Errorf("%w - failed to parse CIDR: %q | %s", WrongFormat, ipRange, err)
			return
		}
		ListOfNetworks = append(ListOfNetworks, r)
	}
	return
}

func NewA(record string, domain string, res resolver) (A, error) {
	q, m, d, cidr4, cidr6, err := matchAMX(record)
	if err != nil {
		return A{}, err
	}
	if m != "a" {
		return A{}, fmt.Errorf("%w - wanted \"a\" got %q", WrongMechanism, m)
	}
	if d != "" {
		domain = d
	}
	networks, err := extractArecordIPs(res, domain, cidr4, cidr6)
	if err != nil {
		return A{}, err
	}
	a := A{
		Record:    record,
		Domain:    domain,
		r:         res,
		CIDR4:     cidr4,
		CIDR6:     cidr6,
		Qualifier: matchQualifier(q),
		Networks:  networks,
	}
	return a, nil
}
