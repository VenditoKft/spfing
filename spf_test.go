package spf

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

type txtDomainPair map[string][]string
type aDomainPair map[string][]net.IP
type mxDomainPair map[string][]*net.MX

type MockResolver struct {
	txtDomains     txtDomainPair
	mxDomains      mxDomainPair
	aDomains       aDomainPair
	errorsToReturn map[string]error
}

func (m MockResolver) TextRecord(domain string) ([]string, error) {
	if v, ok := m.txtDomains[domain]; ok {
		return v, m.errorsToReturn[domain]
	}
	if v, ok := m.errorsToReturn[domain]; ok {
		return []string{}, v
	}
	return []string{}, nil
}
func (m MockResolver) ARecord(domain string) ([]net.IP, error) {
	if v, ok := m.aDomains[domain]; ok {
		return v, m.errorsToReturn[domain]
	}
	if v, ok := m.errorsToReturn[domain]; ok {
		return []net.IP{}, v
	}
	return []net.IP{}, nil
}

func (m MockResolver) MXRecord(domain string) ([]*net.MX, error) {
	if v, ok := m.mxDomains[domain]; ok {
		return v, m.errorsToReturn[domain]
	}
	if v, ok := m.errorsToReturn[domain]; ok {
		return []*net.MX{}, v
	}
	return []*net.MX{}, nil
}

func TestNewSPF(t *testing.T) {
	exampleRecord := "v=spf1 a mx -all"
	testDomain := "test.com"
	txtDomain := make(map[string][]string)
	txtDomain[testDomain] = []string{exampleRecord}
	spf, err := New(testDomain, MockResolver{txtDomains: txtDomain})
	if err != nil {
		t.Errorf("creating SPF should not have failed but got %q", err)
	}
	if spf.Record != exampleRecord {
		t.Errorf("failed to get proper record wanted %q got %q",
			exampleRecord, spf.Record)
	}
}

func TestNewSPFFail(t *testing.T) {
	testDomain := "test.com"
	txtDomain := make(map[string][]string)
	txtDomain[testDomain] = []string{"Not an SPF Record"}
	spf, err := New(testDomain, MockResolver{txtDomains: txtDomain})
	if !errors.Is(err, NoSPFRecordPublished) {
		t.Errorf("did not throw no SPF record error")
	}
	if spf.Record != "" {
		t.Errorf("instead of empty record the following was collected %q",
			spf.Record)
	}
}

func TestSPFMatches(t *testing.T) {
	mainDomain := "test.com"
	TestTable := []struct {
		txtDomains      txtDomainPair
		mxDomains       mxDomainPair
		aDomains        aDomainPair
		ipToMatch       net.IP
		excpectedResult []string
	}{
		{
			txtDomainPair{mainDomain: []string{"v=spf1 a mx -all"}},
			mxDomainPair{mainDomain: []*net.MX{{Host: "mx.test.com"}}},
			aDomainPair{mainDomain: {net.ParseIP("192.168.1.1")},
				"mx.test.com": {net.ParseIP("10.5.5.1")}},
			net.ParseIP("192.168.1.1"),
			[]string{"a"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 a/24 mx -all"}},
			mxDomainPair{mainDomain: []*net.MX{{Host: "mx.test.com"}}},
			aDomainPair{mainDomain: {net.ParseIP("192.168.1.1")},
				"mx.test.com": {net.ParseIP("10.5.5.1")}},
			net.ParseIP("192.168.1.7"),
			[]string{"a/24"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 a mx -all"}},
			mxDomainPair{mainDomain: []*net.MX{{Host: "mx.test.com"}}},
			aDomainPair{mainDomain: {net.ParseIP("192.168.1.1")},
				"mx.test.com": {net.ParseIP("10.5.5.1")}},
			net.ParseIP("10.5.5.1"),
			[]string{"mx"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 a mx/24 -all"}},
			mxDomainPair{mainDomain: []*net.MX{{Host: "mx.test.com"}}},
			aDomainPair{mainDomain: {net.ParseIP("192.168.1.1")},
				"mx.test.com": {net.ParseIP("10.5.5.1")}},
			net.ParseIP("10.5.5.5"),
			[]string{"mx/24"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 a include:subdomain.test.com -all"},
				"subdomain.test.com": []string{"v=spf1 a -all"}},
			mxDomainPair{},
			aDomainPair{mainDomain: {net.ParseIP("192.168.1.1")},
				"subdomain.test.com": {net.ParseIP("10.5.5.1")}},
			net.ParseIP("10.5.5.1"),
			[]string{"include:subdomain.test.com", "a"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 ip4:192.168.1.1/24 -all"}},
			mxDomainPair{},
			aDomainPair{},
			net.ParseIP("192.168.1.15"),
			[]string{"ip4:192.168.1.1/24"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 ip4:192.168.1.1 -all"}},
			mxDomainPair{},
			aDomainPair{},
			net.ParseIP("192.168.1.1"),
			[]string{"ip4:192.168.1.1"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 ip6:2a00:1450:4000::/36 -all"}},
			mxDomainPair{},
			aDomainPair{},
			net.ParseIP("2a00:1450:4000::1"),
			[]string{"ip6:2a00:1450:4000::/36"},
		},
		{
			txtDomainPair{mainDomain: []string{"v=spf1 ip6:2a00:1450:4000:: -all"}},
			mxDomainPair{},
			aDomainPair{},
			net.ParseIP("2a00:1450:4000::"),
			[]string{"ip6:2a00:1450:4000::"},
		},
	}
	for _, testCase := range TestTable {
		spf, err := New(mainDomain, MockResolver{
			txtDomains: testCase.txtDomains,
			mxDomains:  testCase.mxDomains,
			aDomains:   testCase.aDomains})
		if err != nil {
			t.Errorf("creating SPF should not have failed but got %q", err)
		}
		m, err := spf.Match(testCase.ipToMatch)
		if err != nil {
			t.Errorf("matching IP should not have failed but got %q", err)
		}
		if !reflect.DeepEqual(m, testCase.excpectedResult) {
			t.Errorf("wrong result wanted %v got %v", testCase.excpectedResult, m)
		}
	}

}
