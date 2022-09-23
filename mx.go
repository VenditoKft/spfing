package spf

import (
	"fmt"
	"net"
)

type MX struct {
	Qualifier Qualifier
	Record    string
	Domain    string
	CIDR4     string
	CIDR6     string
	r         resolver
	Networks  []*net.IPNet
}

func (mx MX) Match(ip net.IP) (m []string, errRtn error) {
	for _, v := range mx.Networks {
		if v.Contains(ip) {
			m = []string{mx.Record}
			return
		}
	}
	return
}

func extractMXrecordIPs(res resolver, domain string, cidr4 string, cidr6 string) (ListOfNetworks []*net.IPNet, errRtn error) {
	mxRecords, err := res.MXRecord(domain)
	if err != nil {
		errRtn = fmt.Errorf("%w - %s", DNSResolutionError, err)
		return
	}
	for _, mx := range mxRecords {
		ips, err := res.ARecord(mx.Host)
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
	}
	return
}

func NewMX(record string, domain string, res resolver) (MX, error) {
	q, m, d, cidr4, cidr6, err := matchAMX(record)
	if err != nil {
		return MX{}, err
	}
	if m != "mx" {
		return MX{}, fmt.Errorf("%w - wanted \"mx\" got %q", WrongMechanism, m)
	}
	if d != "" {
		domain = d
	}
	networks, err := extractMXrecordIPs(res, domain, cidr4, cidr6)
	if err != nil {
		return MX{}, err
	}
	mx := MX{
		Record:    record,
		Domain:    domain,
		r:         res,
		CIDR4:     cidr4,
		CIDR6:     cidr6,
		Qualifier: matchQualifier(q),
		Networks:  networks,
	}
	return mx, nil
}
