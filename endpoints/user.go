
package endpoints

import "net/http"

type User interface {
	// UserId returns an opaque string that uniquely identifies the user.
	UserId() string

	// Email returns a non-empty email address.
	Email() string

	// AuthDomain returns the URL of the identity provider.
	AuthDomain() string
}

type Provider interface {
	// CurrentOAuthClientID returns a clientId associated with the scope.
	CurrentOAuthClientID(*http.Request, string) (string, error)

	// CurrentOAuthUser returns a user of this request for the given scope.
	// Returns an error if data for this scope is not available.
	CurrentOAuthUser(*http.Request, string) (User, error)
}
