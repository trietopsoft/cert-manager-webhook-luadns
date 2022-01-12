package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/trietopsoft/cert-manager-webhook-luadns/internal"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&luaDNSProviderSolver{},
	)
}

// luaDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type luaDNSProviderSolver struct {
	client kubernetes.Clientset

	recordsMu sync.Mutex
	records   map[string]*internal.DNSRecord
}

// luaDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type luaDNSProviderConfig struct {
	Username        string                   `json:"username"`
	TTL             int                      `json:"ttl"`
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *luaDNSProviderSolver) Name() string {
	return "luadns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *luaDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("unable to load config: %v", err)
	}

	username := cfg.Username
	if username == "" {
		return fmt.Errorf("unable to get Username: %v", err)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 300
	}

	apiKey, err := c.getApiKey(&cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get API Key: %v", err)
	}

	klog.V(2).Infof("Creating LuaDNS client %s %s", username, *apiKey)
	client := internal.NewClient(username, *apiKey)
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	fqdn := ch.ResolvedFQDN
	token := fqdn + ch.Key

	zones, err := client.ListZones()
	if err != nil {
		return fmt.Errorf("luadns: failed to get zones: %w", err)
	}

	zone := findZone(zones, domain)
	if zone == nil {
		return fmt.Errorf("luadns: no matching zone found for domain %s", domain)
	}

	newRecord := internal.DNSRecord{
		Name:    fqdn,
		Type:    "TXT",
		Content: ch.Key,
		TTL:     ttl,
	}

	record, err := client.CreateRecord(*zone, newRecord)
	if err != nil {
		return fmt.Errorf("luadns: failed to create record: %w", err)
	}

	c.recordsMu.Lock()
	c.records[token] = record
	c.recordsMu.Unlock()

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *luaDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	username := cfg.Username
	if username == "" {
		return fmt.Errorf("unable to get Username: %v", err)
	}

	apiKey, err := c.getApiKey(&cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get API Key: %v", err)
	}

	client := internal.NewClient(username, *apiKey)
	fqdn := ch.ResolvedFQDN
	token := fqdn + ch.Key

	c.recordsMu.Lock()
	record, ok := c.records[token]
	c.recordsMu.Unlock()

	if !ok {
		return fmt.Errorf("luadns: unknown record ID for '%s'", fqdn)
	}

	err = client.DeleteRecord(record)
	if err != nil {
		return fmt.Errorf("luadns: failed to delete record: %w", err)
	}

	c.recordsMu.Lock()
	delete(c.records, token)
	c.recordsMu.Unlock()

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *luaDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {

	c.recordsMu = sync.Mutex{}
	c.records = make(map[string]*internal.DNSRecord)

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = *cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (luaDNSProviderConfig, error) {
	cfg := luaDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *luaDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}

// Get LuaDNS API key from Kubernetes secret.
func (c *luaDNSProviderSolver) getApiKey(cfg *luaDNSProviderConfig, namespace string) (*string, error) {
	secretName := cfg.APIKeySecretRef.LocalObjectReference.Name

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}

	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key,
			cfg.APIKeySecretRef.LocalObjectReference.Name, namespace)
	}

	apiKey := string(secBytes)
	return &apiKey, nil
}

func findZone(zones []internal.DNSZone, domain string) *internal.DNSZone {
	var result *internal.DNSZone

	for _, zone := range zones {
		zone := zone
		if zone.Name != "" && strings.HasSuffix(domain, zone.Name) {
			if result == nil || len(zone.Name) > len(result.Name) {
				result = &zone
			}
		}
	}

	return result
}
