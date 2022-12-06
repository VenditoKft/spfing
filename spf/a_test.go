package spf

import (
	"net"
	"testing"
)

type MockAResolver struct {
	toReturn    []net.IP
	txtToReturn []string
	mxToReturn  []*net.MX
	errToReturn error
}

func (m MockAResolver) TextRecord(domain string) ([]string, error) {
	return m.txtToReturn, nil
}

func (m MockAResolver) ARecord(domain string) ([]net.IP, error) {
	if domain == "test2.com" {
		return []net.IP{
			net.ParseIP("192.168.0.1"),
		}, m.errToReturn
	}
	return m.toReturn, m.errToReturn
}

func (m MockAResolver) MXRecord(string) ([]*net.MX, error) {
	return []*net.MX{}, nil
}

func TestNewA(t *testing.T) {
	TestTable := []struct {
		record   string
		returnIP []net.IP
		ip       net.IP
	}{
		{"a",
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("10.0.0.1")},
		{"a:test2.com",
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("192.168.0.1")},
		{"a:test2.com/24",
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("192.168.0.4")},
		{"a/16",
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("10.0.0.9")},
		{"a/26",
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("10.0.0.9")},
	}
	for _, testCase := range TestTable {
		a, err := NewA(testCase.record,
			"test.com",
			MockAResolver{toReturn: testCase.returnIP})
		if err != nil {
			t.Errorf("create a record should not have failed but got %s",
				err)
		}
		m, err := a.Match(testCase.ip)
		if err != nil || len(m) != 1 {
			t.Fatalf("matching record %s to ip %s should not have failed %s but got %q",
				testCase.record,
				testCase.ip,
				err,
				m)
		}
		if m[0] != testCase.record {
			t.Errorf("ip %s did not match record %q with DNS %s",
				testCase.ip,
				testCase.record,
				testCase.returnIP)
		}
	}

}
