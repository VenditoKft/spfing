package spf

import (
	"fmt"
	"net"
)

type All struct {
	Qualifier Qualifier
	Record    string
}

func (a All) Match(ip net.IP) (m []string, errRtn error) {
	return []string{}, nil
}

func NewAll(record string) (All, error) {
	if isALLMechanism(record) {
		qualifier := Pass
		if record != "all" {
			qualifier = matchQualifier(record[0:1])
		}
		return All{Qualifier: qualifier, Record: record}, nil
	}
	return All{}, fmt.Errorf("%w - %s is not all mechanism", WrongFormat, record)
}
