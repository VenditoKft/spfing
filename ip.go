package spf

import (
	"fmt"
	"net"
)

type IP struct {
	Qualifier Qualifier
	Record    string
	Network   *net.IPNet
}

func NewIP(record string) (IP, error) {
	q, v, ip, cidr, err := matchIP(record)
	if err != nil {
		return IP{}, err
	}
	if cidr == "" {
		switch v {
		case "4":
			cidr = "32"
		case "6":
			cidr = "128"
		}
	}
	ipCIDR := fmt.Sprintf("%s/%s", ip, cidr)
	_, network, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return IP{}, fmt.Errorf("%w - IP not parseable %s", WrongFormat, err)
	}
	i := IP{
		Qualifier: matchQualifier(q),
		Record:    record,
		Network:   network,
	}
	return i, nil
}

func (i IP) Match(ip net.IP) (m []string, errRtn error) {
	if i.Network.Contains(ip) {
		m = append(m, i.Record)
	}
	return
}
