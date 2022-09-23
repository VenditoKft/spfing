package spf

import (
	"net"
)

type Include struct {
	Qualifier Qualifier
	Domain    string
	Record    string
	r         resolver
	spf       SPF
}

func NewInclude(record string, res resolver) (Include, error) {
	q, d, err := matchInclude(record)
	if err != nil {
		return Include{}, err
	}
	spf, err := New(d, res)
	if err != nil {
		return Include{}, err
	}
	i := Include{
		Qualifier: matchQualifier(q),
		r:         res,
		Record:    record,
		Domain:    d,
		spf:       spf,
	}
	return i, nil
}

func (i Include) Match(ip net.IP) ([]string, error) {
	m, err := i.spf.Match(ip)
	if err != nil {
		return []string{}, err
	}
	if len(m) > 0 {
		m = append([]string{i.Record}, m...)
	}
	return m, nil
}
