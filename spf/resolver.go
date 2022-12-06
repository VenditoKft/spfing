package spf

import (
	"context"
	"net"
	"time"
)

type resolver interface {
	TextRecord(string) ([]string, error)
	ARecord(string) ([]net.IP, error)
	MXRecord(string) ([]*net.MX, error)
}

type defaultResolver struct {
	count    int
	resolver *net.Resolver
}

var GoogleResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Millisecond * time.Duration(10000),
		}
		return d.DialContext(ctx, network, "8.8.8.8:53")
	},
}

func NewDefaultResolver() defaultResolver {
	return defaultResolver{count: 0}
}

func NewGoogleResolver() defaultResolver {
	return defaultResolver{count: 0, resolver: GoogleResolver}
}

func (r defaultResolver) TextRecord(domain string) ([]string, error) {
	r.count = r.count + 1
	if r.resolver != nil {
		return r.resolver.LookupTXT(context.Background(), domain)
	}
	return net.LookupTXT(domain)
}

func (r defaultResolver) ARecord(domain string) ([]net.IP, error) {
	r.count = r.count + 1
	if r.resolver != nil {
		addrs, err := r.resolver.LookupIPAddr(context.Background(), domain)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, len(addrs))
		for i, ia := range addrs {
			ips[i] = ia.IP
		}
		return ips, nil
	}
	return net.LookupIP(domain)
}

func (r defaultResolver) MXRecord(domain string) ([]*net.MX, error) {
	r.count = r.count + 1
	if r.resolver != nil {
		return r.resolver.LookupMX(context.Background(), domain)
	}
	return net.LookupMX(domain)
}
