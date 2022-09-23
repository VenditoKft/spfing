package spf

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsIP(t *testing.T) {
	TestTable := []struct {
		record string
	}{
		{"ip4:192.168.1.1"},
		{"ip4:192.168.1.1/24"},
		{"ip6:2001:4860:4000::/36"},
		{"ip6:2800:3f0:4000::/36"},
	}
	for _, testCase := range TestTable {
		if !isIPMechanism(testCase.record) {
			t.Errorf("record %s was not recognised", testCase.record)
		}
	}

}

func TestMatchAMX(t *testing.T) {
	TestTable := []struct {
		part       string
		qualifier  string
		mechanism  string
		domain     string
		cidr4      string
		cidr6      string
		shouldFail bool
	}{
		{"a", "+", "a", "", "", "", false},
		{"-a", "-", "a", "", "", "", false},
		{"~a", "~", "a", "", "", "", false},
		{"a/14/64", "+", "a", "", "14", "64", false},
		{"a:test.com", "+", "a", "test.com", "", "", false},
		{"a:test.com/24/48", "+", "a", "test.com", "24", "48", false},
		{"a:t^est.com", "+", "a", "", "", "", true},
		{"a:t^est.com/24/48", "+", "", "", "", "", true},
		{"a:test.com/44/48", "+", "", "", "", "", true},
		{"a:test.com/24/148", "+", "", "", "", "", true},
		{"a/44/64", "+", "a", "", "", "", true},
		{"a/14/464", "+", "a", "", "", "", true},
		{"mx", "+", "mx", "", "", "", false},
		{"-mx", "-", "mx", "", "", "", false},
		{"~mx", "~", "mx", "", "", "", false},
		{"mx/24/128", "+", "mx", "", "24", "128", false},
		{"mx/14/64", "+", "mx", "", "14", "64", false},
		{"mx:test.com", "+", "mx", "test.com", "", "", false},
		{"mx:test.com/24/48", "+", "mx", "test.com", "24", "48", false},
		{"-mx:test.com/24/48", "-", "mx", "test.com", "24", "48", false},
		{"~mx:test.com/24/48", "~", "mx", "test.com", "24", "48", false},
		{"mx:t^est.com", "+", "mx", "", "", "", true},
		{"mx:t^est.com/24/48", "+", "", "", "", "", true},
		{"mx:test.com/44/48", "+", "", "", "", "", true},
		{"mx:test.com/24/148", "+", "", "", "", "", true},
		{"mx/44/64", "+", "mx", "", "", "", true},
		{"mx/14/464", "+", "mx", "", "", "", true},
		{"something", "+", "", "", "", "", true},
	}
	for _, testCase := range TestTable {
		q, m, d, c4, c6, err := matchAMX(testCase.part)
		if testCase.shouldFail && err == nil {
			t.Errorf("mechanism %s should have failed got %q",
				testCase.part,
				m)
		}
		if !testCase.shouldFail {
			if err != nil {
				t.Errorf("mechanism %s should not have failed but got %q",
					testCase.part,
					err)
			}
			if q != testCase.qualifier {
				t.Errorf("wrong qualifier match wanted %q got %q",
					testCase.qualifier,
					q)
			}
			if m != testCase.mechanism {
				t.Errorf("wrong mechanism match wanted %q got %q",
					testCase.mechanism,
					m)
			}
			if d != testCase.domain {
				t.Errorf("wrong domain match wanted %q got %q",
					testCase.domain,
					d)
			}
			if c4 != testCase.cidr4 {
				t.Errorf("wrong CIDR4 match wanted %q got %q",
					testCase.cidr4,
					c4)
			}
			if c6 != testCase.cidr6 {
				t.Errorf("wrong CIDR6 match wanted %q got %q",
					testCase.cidr6,
					c6)
			}
		}
	}

}

func TestMatchInclude(t *testing.T) {
	TestTable := []struct {
		domain       string
		qualifier    string
		errExcpected error
	}{
		{"test.com", "", nil},
		{"testing.com", "-", nil},
		{"wrong.com", "!", WrongFormat},
	}
	for _, testCase := range TestTable {
		record := fmt.Sprintf("%sinclude:%s",
			testCase.qualifier,
			testCase.domain)
		q, d, err := matchInclude(record)
		if !errors.Is(err, testCase.errExcpected) {
			t.Errorf("expected error %q got %q",
				testCase.errExcpected,
				err)
		}
		if err != nil {
			continue
		}
		if d != testCase.domain {
			t.Errorf("wrong domain wanted %s got %s",
				testCase.domain,
				d)
		}
		if q != testCase.qualifier {
			t.Errorf("wrong qualifier wanted %s got %s",
				testCase.qualifier,
				q)
		}
	}

}
