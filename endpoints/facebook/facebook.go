
package facebook

import (
	"net/http"
	"github.com/rwl/go-endpoints/endpoints"
	"fmt"
	"log"
	"encoding/json"
	"errors"
)

const debugUri = "https://graph.facebook.com/debug_token?input_token=%s&access_token=%s"
const graphUri = "https://graph.facebook.com/me?access_token=%s"

/*
"data": {
	"app_id": 138483919580948,
	"application": "Social Cafe",
	"expires_at": 1352419328,
	"is_valid": true,
	"issued_at": 1347235328,
	"metadata": {
		"sso": "iphone-safari"
	},
	"scopes": [
		"email",
		"publish_actions"
	],
	"user_id": 1207059
}
*/
type debugResponse struct {
	Data *Data `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`
}

type Data struct {
	AppId int64 `json:"app_id"`
	Application string `json:"application"`
	ExpiresAt int64 `json:"expires_at"`
	IsValid bool `json:"is_valid"`
	IssuedAt int64 `json:"issued_at"`
	Metadata map[string]string `json:"metadata"`
	Scopes []string `json:"scopes"`
	UserId int64 `json:"user_id"`
}

/*
"error": {
 "message": "Message describing the error",
 "type": "OAuthException",
 "code": 190 ,
 "error_subcode": 460
}
*/
type Error struct {
	Message string `json:"message"`
	Type string `json:"type"`
	Code int `json:"code"`
	Subcode int `json:"error_subcode"`
}

type FacebookUser struct {
	Id string `json:"id"` // User ID.
	Link string `json:"link"` // Timeline link.
	FirstName string `json:"first_name"`
	Quotes string `json:"quotes"` // Favorite quotes.
	Name string `json:"name"` // Full name.
	Hometown string `json:"hometown"`
	Bio string `json:"bio"`
	Religion string `json:"religion"`
	MiddleName string `json:"middle_name"`
	About string `json:"about"` // About the user.
	IsVerified bool `json:"is_verified"` // Verified by Facebook.
	Gender string `json:"gender"`
	ThirdPartyId string `json:"third_party_id"` // A string containing an anonymous, but unique identifier for the user.
	RelationshipStatus string `json:"relationship_status"`
	LastName string `json:"last_name"`
	Verified bool `json:"verified"` // Verified via mobile registration, SMS or credit card.
	Political string `json:"political"` // Political views.
	NameFormat string `json:"name_format"` // The user's name formatted to correctly handle Chinese, Japanese, Korean ordering.
	SignificantOther string `json:"significant_other"`
	Website string `json:"website"`
	Location string `json:"location"`
	Username string `json:"username"`
}

func (u *FacebookUser) UserId() string {
	return u.Id
}

func (u *FacebookUser) Email() string {
	return ""
}

func (u *FacebookUser) AuthDomain() string {
	return "graph.facebook.com"
}

func fetchTokenData(token, appOrDevId string) (*Data, error) {
	url := fmt.Sprintf(debugUri, token, appOrDevId)
	log.Printf("Fetching token data from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	d := &debugResponse{}
	if err = json.NewDecoder(resp.Body).Decode(d); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Error fetching tokeninfo (status %d)", resp.StatusCode)
		if d.Error != nil && d.Error.Message != "" {
			errMsg += ": " + d.Error.Message
		}
		return nil, errors.New(errMsg)
	}

	switch {
	case d.Data == nil:
		return nil, errors.New("No token data received")
	case !d.Data.IsValid:
		return nil, errors.New("Token is not valid")
	}

	return d.Data, err
}

func getScopedTokenData(req *http.Request, scope, appOrDevId string) (*Data, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}
	d, err := fetchTokenData(token, appOrDevId)
	if err != nil {
		return nil, err
	}
	for _, s := range d.Scopes {
		if s == scope {
			return d, nil
		}
	}
	return nil, fmt.Errorf("No scope matches: expected one of %q, got %q",
		d.Scopes, scope)
}

func fetchGraphData(req *http.Request) (*FacebookUser, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}

	url := fmt.Sprintf(graphUri, token)
	log.Printf("Fetching graph data from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	fu := &FacebookUser{}
	if err = json.NewDecoder(resp.Body).Decode(fu); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error fetching tokeninfo (status %d)", resp.StatusCode)
	}

	return fu, err
}

type FacebookProvider struct {
	appOrDevId string // App access token or a valid user access token from a developer of the app.
}

// CurrentOAuthClientID returns a clientId associated with the scope.
func (p *FacebookProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
	ti, err := getScopedTokenData(req, scope, p.appOrDevId)
	if err != nil {
		return "", err
	}
	return ti.IssuedTo, nil
}

// CurrentOAuthUser returns a user associated with the request in context.
func (p *FacebookProvider) CurrentOAuthUser(req *http.Request, scope string) (*endpoints.User, error) {
	// FIXME: Filter according to scope
	p, err := fetchGraphData(req)
	if err != nil {
		return nil, err
	}
	return p, nil
}
