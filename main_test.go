package main

import (
	"os"
	"testing"

	"github.com/jetstack/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
	host = os.Getenv("TEST_HOST_NAME")
)

func TestRunsSuite(t *testing.T) {
	if zone != "" {
		fqdn := host
		if fqdn != "" {
			fqdn += "." + zone
		}
		fixture := dns.NewFixture(&luaDNSProviderSolver{},
			dns.SetStrict(true),
			dns.SetResolvedFQDN(fqdn),
			dns.SetResolvedZone(zone),
			dns.SetUseAuthoritative(true),
			dns.SetAllowAmbientCredentials(false),
			dns.SetManifestPath("testdata/luadns-solver"),
			dns.SetBinariesPath("_test/kubebuilder/bin"),
		)
		fixture.RunConformance(t)
	} else {
		t.Fatal("Please provide env:TEST_ZONE_NAME")
		t.FailNow()
	}
}
