// This implementation of the Provider interface uses the Amazon tokeninfo
// and profile APIs to validate bearer token.

package amazon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"log"
	"github.com/rwl/go-endpoints/endpoints"
)

// Made variable for testing purposes.
var tokeninfoEndpointUrl = "https://api.amazon.com/auth/O2/tokeninfo"
var profileEndpointUrl = "https://api.amazon.com/user/profile"

type AmazonProvider struct {}

// CurrentOAuthClientID returns a clientId associated with the access token.
func (p *AmazonProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
	// FIXME: Filter according to scope
	ti, err := getTokeninfo(req)
	if err != nil {
		return "", err
	}
	return ti.IssuedTo, nil
}

// CurrentOAuthUser returns a user associated with the request in context.
func (p *AmazonProvider) CurrentOAuthUser(req *http.Request, scope string) (*endpoints.User, error) {
	// FIXME: Filter according to scope
	p, err := getProfile(req)
	if err != nil {
		return nil, err
	}
	return p, nil
}

type tokeninfo struct {
	// The issuer identifier. This will be https://www.amazon.com
	Issuer string `json:"iss"`

	// The user ID of the account linked to the access token. This is unique for each user
	// and takes the form of amzn1.account.K2LI23KL2LK2.
	UserId string `json:"user_id"`

	// The client identifier used to request the access token. If this does not match the
	// client_id used in your authorization request do not use this token.
	IssuedTo string `json:"aud"`

	// The application identifer of the application that requested the token.
	ApplicationId string `json:"app_id"`

	// The remaining lifetime of the access token, in seconds.
	ExpiresIn int `json:"exp"`

	// The time the token was issued. The value is number of seconds from 1970-01-01T0:0:0Z as measured in UTC.
	IssuedAt int64 `json:"iat"`

	// ErrorDescription is populated when an error occurs. Usually, the response
	// either contains only ErrorDescription or the fields above
	ErrorDescription string `json:"error_description"`
}

// fetchTokeninfo retrieves token info from tokeninfoEndpointUrl (tokeninfo API)
func fetchTokeninfo(token string) (*tokeninfo, error) {
	url := tokeninfoEndpointUrl + "?access_token=" + token
	log.Printf("Fetching token info from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ti := &tokeninfo{}
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
	case ti.UserId == "":
		return nil, fmt.Errorf("Invalid user ID")
	}

	return ti, err
}

func getTokeninfo(req *http.Request) (*tokeninfo, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}
	ti, err := fetchTokeninfo(token)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

type AmazonUser struct {
	UserId string `json:"user_id"` // scopes: profile profile:user_id
	Email         string `json:"email"`// scope: profile
	Name         string `json:"name"`// scope: profile
	PostalCode string `json:"postal_code"`// scope: postal_code
	// ErrorDescription is populated when an error occurs. Usually, the response
	// either contains only ErrorDescription or the fields above
	ErrorDescription string `json:"error_description"`
}

func (u *AmazonUser) UserId() string {
	return u.UserId
}

func (u *AmazonUser) Email() string {
	return u.Email
}

func (u *AmazonUser) AuthDomain() string {
	return "https://www.amazon.com"
}

// fetchProfile retrieves token info from profileEndpointUrl
func fetchProfile(token string) (*AmazonUser, error) {
	url := profileEndpointUrl + "?access_token=" + token
	log.Printf("Fetching profile from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	p := &AmazonUser{}
	if err = json.NewDecoder(resp.Body).Decode(p); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Error fetching profile (status %d)", resp.StatusCode)
		if p.ErrorDescription != "" {
			errMsg += ": " + p.ErrorDescription
		}
		return nil, errors.New(errMsg)
	}

	return p, err
}

func getProfile(req *http.Request) (*AmazonUser, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}
	p, err := fetchProfile(token)
	if err != nil {
		return nil, err
	}
	return p, nil
}
