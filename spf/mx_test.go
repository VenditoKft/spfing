package spf

import (
	"net"
	"testing"
)

type MockMXResolver struct {
	toReturn    []*net.MX
	ipToReturn  []net.IP
	errToReturn error
}

func (m MockMXResolver) TextRecord(domain string) ([]string, error) {
	return []string{}, nil
}

func (m MockMXResolver) ARecord(domain string) ([]net.IP, error) {
	if domain == "test.test2.com" {
		return []net.IP{net.ParseIP("192.168.0.1")}, nil
	}
	return m.ipToReturn, nil
}

func (m MockMXResolver) MXRecord(domain string) ([]*net.MX, error) {
	if domain == "test2.com" {
		return []*net.MX{{Host: "test.test2.com"}}, m.errToReturn
	}
	return m.toReturn, m.errToReturn
}

func TestNewMX(t *testing.T) {
	TestTable := []struct {
		record      string
		mxHost      []*net.MX
		ipsToReturn []net.IP
		ip          net.IP
	}{
		{"mx",
			[]*net.MX{{Host: "test.com"}},
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("10.0.0.1")},
		{"mx/24",
			[]*net.MX{{Host: "test.com"}},
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("10.0.0.20")},
		{"mx:test2.com",
			[]*net.MX{{Host: "test.com"}},
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("192.168.0.1")},
		{"mx:test2.com/16",
			[]*net.MX{{Host: "test.com"}},
			[]net.IP{net.ParseIP("10.0.0.1")},
			net.ParseIP("192.168.1.1")},
	}
	for _, testCase := range TestTable {
		a, err := NewMX(testCase.record,
			"test.com",
			MockMXResolver{toReturn: testCase.mxHost, ipToReturn: testCase.ipsToReturn})
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
				testCase.ipsToReturn)
		}
	}

}
