
package facebook

import (
	"net/http"
	"github.com/rwl/go-endpoints/endpoints"
)

const endpointUri = "graph.facebook.com/debug_token?input_token=%s&access_token=%s"
const graphUri = "https://graph.facebook.com/me?"

/*
    {
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
    }

    {
       "error": {
         "message": "Message describing the error",
         "type": "OAuthException",
         "code": 190 ,
         "error_subcode": 460
       }
    }
*/

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

type FacebookProvider struct {
	accessToken string // App access token or a valid user access token from a developer of the app.
}

// CurrentOAuthClientID returns a clientId associated with the scope.
func (p *FacebookProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
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
