package spf

import (
	"fmt"
	"net"
	"testing"
)

func TestNewIPHappyPath(t *testing.T) {
	TestTable := []struct {
		ip   string
		v    string
		cidr string
	}{
		{"10.5.5.5", "4", "10.5.5.5/32"},
		{"10.5.5.5/24", "4", "10.5.5.1/24"},
		{"2001:4860:4000::/36", "6", "2001:4860:4000::/36"},
		{"2800:3f0:4000::/36", "6", "2800:3f0:4000::/36"},
		{"2800:3f0:4000::", "6", "2800:3f0:4000::/128"},
	}
	for _, testCase := range TestTable {
		record := fmt.Sprintf("ip%s:%s", testCase.v, testCase.ip)
		i, err := NewIP(record)
		if err != nil {
			t.Errorf("should not have failed but got %q", err)
		}
		_, cidr, _ := net.ParseCIDR(testCase.cidr)
		if cidr.String() != i.Network.String() {
			t.Errorf("wanted network %v but got %v", cidr, i.Network)
		}
	}

}
