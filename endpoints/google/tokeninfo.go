// This implementation of the Provider interface uses tokeninfo API to validate
// bearer token.
// 
// It is intended to be used only in development.

package google

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"log"
	"github.com/rwl/go-endpoints/endpoints"
	"time"
)

const CertUri = ("https://www.googleapis.com/service_accounts/" +
		"v1/metadata/raw/federated-signon@system.gserviceaccount.com")
const Issuer = "accounts.google.com"

// Made variable for testing purposes.
var tokeninfoEndpointUrl = "https://www.googleapis.com/oauth2/v2/tokeninfo"

type GoogleUser struct {
	IssuedTo      string `json:"issued_to"`
	Audience      string `json:"audience"`
	UserId        string `json:"user_id"`
	Scope         string `json:"scope"`
	ExpiresIn     int    `json:"expires_in"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	AccessType    string `json:"access_type"`
	// ErrorDescription is populated when an error occurs. Usually, the response
	// either contains only ErrorDescription or the fields above
	ErrorDescription string `json:"error_description"`
}

func (u *GoogleUser) UserId() string {
	return u.UserId
}

func (u *GoogleUser) Email() string {
	return u.Email
}

func (u *GoogleUser) AuthDomain() string {
	return Issuer
}

// fetchTokeninfo retrieves token info from tokeninfoEndpointUrl (tokeninfo API)
func fetchTokeninfo(token string) (*GoogleUser, error) {
	url := tokeninfoEndpointUrl + "?access_token=" + token
	log.Printf("Fetching token info from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ti := &GoogleUser{}
	if err = json.NewDecoder(resp.Body).Decode(ti); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Error fetching tokeninfo (status %d)", resp.StatusCode)
		if ti.ErrorDescription != "" {
			errMsg += ": " + ti.ErrorDescription
		}
		return nil, errors.New(errMsg)
	}

	switch {
	case ti.ExpiresIn <= 0:
		return nil, errors.New("Token is expired")
	case !ti.VerifiedEmail:
		return nil, fmt.Errorf("Unverified email %q", ti.Email)
	case ti.Email == "":
		return nil, fmt.Errorf("Invalid email address")
	}

	return ti, err
}

// getScopedTokeninfo validates fetched token by matching tokeinfo.Scope
// with scope arg.
func getScopedTokeninfo(req *http.Request, scope string) (*GoogleUser, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}
	ti, err := fetchTokeninfo(token)
	if err != nil {
		return nil, err
	}
	for _, s := range strings.Split(ti.Scope, " ") {
		if s == scope {
			return ti, nil
		}
	}
	return nil, fmt.Errorf("No scope matches: expected one of %q, got %q",
		ti.Scope, scope)
}

// A context that uses tokeninfo API to validate bearer token.
type TokenInfoProvider struct {
	cache *endpoints.CertsList
	expiresAt time.Time
}

func NewTokenInfoProvider() *TokenInfoProvider {
	return &TokenInfoProvider{}
}

// CurrentOAuthClientID returns a clientId associated with the scope.
func (p *TokenInfoProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
	ti, err := getScopedTokeninfo(req, scope)
	if err != nil {
		return "", err
	}
	return ti.IssuedTo, nil
}

// CurrentOAuthUser returns a user associated with the request in context.
func (p *TokenInfoProvider) CurrentOAuthUser(req *http.Request, scope string) (*endpoints.User, error) {
	ti, err := getScopedTokeninfo(req, scope)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

func (p *TokenInfoProvider) CachedCerts() *endpoints.CertsList {
	if time.Now().UTC().Before(p.expiresAt) {
		return p.cache
	}
	return nil
}

func (p *TokenInfoProvider) CacheCerts(certs *endpoints.CertsList, expiration time.Duration) {
	p.expiresAt = time.Now().UTC().Add(expiration)
	p.cache = certs
}

func (p *TokenInfoProvider) CertUri() string {
	return CertUri
}

func (p *TokenInfoProvider) Issuer() string {
	return Issuer
}
