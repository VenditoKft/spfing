package spf

import "net"

type resolver interface {
	TextRecord(string) ([]string, error)
	ARecord(string) ([]net.IP, error)
	MXRecord(string) ([]*net.MX, error)
}

type defaultResolver struct {
	count int
}

func NewDefaultResolver() defaultResolver {
	return defaultResolver{count: 0}
}

func (r defaultResolver) TextRecord(domain string) ([]string, error) {
	r.count = r.count + 1
	return net.LookupTXT(domain)
}

func (r defaultResolver) ARecord(domain string) ([]net.IP, error) {
	r.count = r.count + 1
	return net.LookupIP(domain)
}

func (r defaultResolver) MXRecord(domain string) ([]*net.MX, error) {
	r.count = r.count + 1
	return net.LookupMX(domain)
}
