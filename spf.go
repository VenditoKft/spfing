package spf

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type Qualifier int

const (
	Pass Qualifier = iota
	Fail
	Softfail
	Neutral
)

var (
	WrongFormat          = errors.New("wrong mechanism format")
	WrongMechanism       = errors.New("wrong mechanism")
	DNSResolutionError   = errors.New("failed to resolve domain")
	NoSPFRecordPublished = errors.New("no spf record found under the domain")
)

type Mechanism interface {
	Match(net.IP) ([]string, error)
}

type SPF struct {
	Record     string
	Domain     string
	r          resolver
	Mechanisms []Mechanism
}

func (spf *SPF) Parse() error {
	s := strings.Split(spf.Record, " ")
	for _, v := range s {
		if v == "v=spf1" {
			continue
		}
		if IsAMechanism(v) {
			m, err := NewA(v, spf.Domain, spf.r)
			if err != nil {
				return err
			}
			spf.Mechanisms = append(spf.Mechanisms, m)
			continue
		}
		if isMXMechanism(v) {
			m, err := NewMX(v, spf.Domain, spf.r)
			if err != nil {
				return err
			}
			spf.Mechanisms = append(spf.Mechanisms, m)
			continue
		}
		if isALLMechanism(v) {
			m, err := NewAll(v)
			if err != nil {
				return err
			}
			spf.Mechanisms = append(spf.Mechanisms, m)
			continue
		}
		if IsIncludeMechanism(v) {
			m, err := NewInclude(v, spf.r)
			if err != nil {
				return err
			}
			spf.Mechanisms = append(spf.Mechanisms, m)
			continue
		}
		if isIPMechanism(v) {
			m, err := NewIP(v)
			if err != nil {
				return err
			}
			spf.Mechanisms = append(spf.Mechanisms, m)
			continue
		}
	}
	return nil
}

func (spf *SPF) Match(ip net.IP) (match []string, errRtn error) {
	for _, v := range spf.Mechanisms {
		m, err := v.Match(ip)
		if err != nil {
			return []string{}, err
		}
		if len(m) > 0 {
			return m, nil
		}
	}
	return []string{}, nil
}

func New(domain string, res resolver) (spf SPF, errRtn error) {
	spf.Domain = domain
	spf.r = res
	txt, err := res.TextRecord(domain)
	if err != nil {
		errRtn = fmt.Errorf("%w - %s", DNSResolutionError, err)
	}
	for _, v := range txt {
		if strings.HasPrefix(v, "v=spf1") {
			spf.Record = v
			break
		}
	}
	if spf.Record == "" {
		errRtn = fmt.Errorf("%w @ %s", NoSPFRecordPublished, domain)
		return
	}
	errRtn = spf.Parse()
	return
}
