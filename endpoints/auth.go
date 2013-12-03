package endpoints

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"log"
	"io/ioutil"
)

const (
	ClockSkewSecs        = 300
	MaxTokenLifetimeSecs = 86400
)

var (
	allowedAuthSchemesUpper = [2]string{"OAUTH", "BEARER"}
	clockSkewSecs           = int64(300)   // 5 minutes in seconds
	maxTokenLifetimeSecs    = int64(86400) // 1 day in seconds
	maxAgePattern           = regexp.MustCompile(`\s*max-age\s*=\s*(\d+)\s*`)

	// This is a variable on purpose: can be stubbed with a different (fake)
	// implementation during tests.
	// 
	// endpoints package code should always call jwtParser()
	// instead of directly invoking verifySignedJwt().
//	jwtParser = verifySignedJwt

	// currentUTC returns current time in UTC.
	// This is a variable on purpose to be able to stub during testing.
	currentUTC = func() time.Time {
		return time.Now().UTC()
	}

	// ContextFactory takes an in-flight HTTP request and creates a new
	// context.
	//
	// It is a variable on purpose. You can set it to a stub implementation
	// in tests.
//	ContextFactory func(*http.Request) Context

	authProviders = []Provider
)

type Provider interface {
	// CurrentOAuthClientID returns a clientId associated with the scope.
	CurrentOAuthClientID(*http.Request, string) (string, error)

	// CurrentOAuthUser returns a user of this request for the given scope.
	// Returns an error if data for this scope is not available.
	CurrentOAuthUser(*http.Request, string) (User, error)
}

type CertProvider interface {
	CertUri() string
	Issuer() string
}

type CachingProvider interface {
	CachedCerts() *CertsList
	CacheCerts(*CertsList, time.Duration)
}

type ClientProvider interface {
	Client() *http.Client
}

type User interface {
	// UserId returns an opaque string that uniquely identifies the user.
	UserId() string

	// Email returns a non-empty email address.
	Email() string

	// AuthDomain returns the URL of the identity provider.
	AuthDomain() string
}

type JwtUser struct {
	email string
}

func (u *JwtUser) UserId() string {
	return ""
}

func (u *JwtUser) Email() string {
	return u.email
}

func (u *JwtUser) AuthDomain() string {
	return ""
}

// GetToken looks for Authorization header and returns a token.
// 
// Returns empty string if req does not contain authorization header
// or its value is not prefixed with allowedAuthSchemesUpper.
func GetToken(req *http.Request) string {
	// TODO(dhermes): Allow a struct with access_token and bearer_token
	//                fields here as well.
	pieces := strings.Fields(req.Header.Get("Authorization"))
	if len(pieces) != 2 {
		return ""
	}
	authHeaderSchemeUpper := strings.ToUpper(pieces[0])
	for _, authScheme := range allowedAuthSchemesUpper {
		if authHeaderSchemeUpper == authScheme {
			return pieces[1]
		}
	}
	return ""
}

type CertInfo struct {
	Algorithm string `json:"algorithm"`
	Exponent  string `json:"exponent"`
	KeyID     string `json:"keyid"`
	Modulus   string `json:"modulus"`
}

type CertsList struct {
	KeyValues []*CertInfo `json:"keyvalues"`
}

// getMaxAge parses Cache-Control header value and extracts
// max-age (in seconds)
func getMaxAge(s string) int {
	match := maxAgePattern.FindStringSubmatch(s)
	if len(match) != 2 {
		return 0
	}
	if maxAge, err := strconv.Atoi(match[1]); err == nil {
		return maxAge
	}
	return 0
}

// getCertExpirationTime computes a cert freshness based on Cache-Control
// and Age headers of h.
// 
// Returns 0 if one of the required headers is not present or cert lifetime
// is expired.
func getCertExpirationTime(h http.Header) time.Duration {
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2 indicates only
	// a comma-separated header is valid, so it should be fine to split this on
	// commas.
	var maxAge int
	for _, entry := range strings.Split(h.Get("Cache-Control"), ",") {
		maxAge = getMaxAge(entry)
		if maxAge > 0 {
			break
		}
	}
	if maxAge <= 0 {
		return 0
	}

	age, err := strconv.Atoi(h.Get("Age"))
	if err != nil {
		return 0
	}

	remainingTime := maxAge - age
	if remainingTime <= 0 {
		return 0
	}

	return time.Duration(remainingTime) * time.Second
}

// GetCachedCerts fetches public certificates info from DefaultCertUri and
// caches it for the duration specified in Age header of a response.
func getCachedCerts(cp CertProvider) (*CertsList, error) {
	cachingProvider, caching := cp.(CachingProvider)

	var certs *CertsList
	if (caching) {
		certs, err := cachingProvider.CachedCerts()

		if err == nil && certs != nil {
			return certs, nil
		}
	}

	var client *http.Client
	clientProvider, ok := cp.(ClientProvider)
	if ok {
		client = clientProvider.Client()
	} else {
		client = &http.Client{}
	}
	resp, err := client.Get(cp.CertUri())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("Could not reach Cert URI")
	}

	certBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(certBytes, &certs)
	if err != nil {
		return nil, err
	}

	if caching {
		expiration := getCertExpirationTime(resp.Header)
		if expiration > 0 {
			cachingProvider.CacheCerts(certs, expiration)
		}
	}
	return certs, nil
}

type signedJWTHeader struct {
	Algorithm string `json:"alg"`
}

type signedJWT struct {
	Audience string `json:"aud"`
	ClientID string `json:"azp"`
	Email    string `json:"email"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Issuer   string `json:"iss"`
}

// addBase64Pad pads s to be a valid base64-encoded string.
func addBase64Pad(s string) string {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return s
}

// base64ToBig converts base64-encoded string to a big int.
// Returns error if the encoding is invalid.
func base64ToBig(s string) (*big.Int, error) {
	b, err := base64.StdEncoding.DecodeString(addBase64Pad(s))
	if err != nil {
		return nil, err
	}
	z := big.NewInt(0)
	z.SetBytes(b)
	return z, nil
}

// zeroPad prepends 0s to b so that length of the returned slice is size.
func zeroPad(b []byte, size int) []byte {
	padded := make([]byte, size-len(b), size)
	return append(padded, b...)
}

// contains returns true if value is one of the items of strList.
func contains(strList []string, value string) bool {
	for _, choice := range strList {
		if choice == value {
			return true
		}
	}
	return false
}

// verifySignedJwt decodes and verifies JWT token string.
// 
// Verification is based on
//   - a certificate exponent and modulus
//   - expiration and issue timestamps ("exp" and "iat" fields)
// 
// This method expects JWT token string to be in the standard format, e.g. as
// read from Authorization request header: "<header>.<payload>.<signature>",
// where all segments are encoded with URL-base64.
// 
// The caller is responsible for performing further token verification.
// (Issuer, Audience, ClientID, etc.)
// 
// NOTE: do not call this function directly, use jwtParser() instead.
func verifySignedJwt(cp CertProvider, jwt string, now int64) (*signedJWT, error) {
	segments := strings.Split(jwt, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("Wrong number of segments in token: %s", jwt)
	}

	// Check that header (first segment) is valid
	headerBytes, err := base64.URLEncoding.DecodeString(addBase64Pad(segments[0]))
	if err != nil {
		return nil, err
	}
	var header signedJWTHeader
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != "RS256" {
		return nil, fmt.Errorf("Unexpected encryption algorithm: %s", header.Algorithm)
	}

	// Check that token (second segment) is valid
	tokenBytes, err := base64.URLEncoding.DecodeString(addBase64Pad(segments[1]))
	if err != nil {
		return nil, err
	}
	var token signedJWT
	err = json.Unmarshal(tokenBytes, &token)
	if err != nil {
		return nil, err
	}

	// Get current certs
	certs, err := getCachedCerts(cp)
	if err != nil {
		return nil, err
	}

	signatureBytes, err := base64.URLEncoding.DecodeString(addBase64Pad(segments[2]))
	if err != nil {
		return nil, err
	}
	signature := big.NewInt(0)
	signature.SetBytes(signatureBytes)

	signed := []byte(fmt.Sprintf("%s.%s", segments[0], segments[1]))
	h := sha256.New()
	h.Write(signed)
	signatureHash := h.Sum(nil)
	if len(signatureHash) < 32 {
		signatureHash = zeroPad(signatureHash, 32)
	}

	z := big.NewInt(0)
	verified := false
	for _, cert := range certs.KeyValues {
		exponent, err := base64ToBig(cert.Exponent)
		if err != nil {
			return nil, err
		}
		modulus, err := base64ToBig(cert.Modulus)
		if err != nil {
			return nil, err
		}
		signatureHashFromCert := z.Exp(signature, exponent, modulus).Bytes()
		// Only consider last 32 bytes
		if len(signatureHashFromCert) > 32 {
			firstIndex := len(signatureHashFromCert) - 32
			signatureHashFromCert = signatureHashFromCert[firstIndex:]
		} else if len(signatureHashFromCert) < 32 {
			signatureHashFromCert = zeroPad(signatureHashFromCert, 32)
		}
		verified = bytes.Equal(signatureHash, signatureHashFromCert)
		if verified {
			break
		}
	}

	if !verified {
		return nil, fmt.Errorf("Invalid token signature: %s", jwt)
	}

	// Check time
	if token.IssuedAt == 0 {
		return nil, fmt.Errorf("Invalid iat value in token: %s", tokenBytes)
	}
	earliest := token.IssuedAt - clockSkewSecs
	if now < earliest {
		return nil, fmt.Errorf("Token used too early, %d < %d: %s", now, earliest, tokenBytes)
	}

	if token.Expires == 0 {
		return nil, fmt.Errorf("Invalid exp value in token: %s", tokenBytes)
	} else if token.Expires >= now+maxTokenLifetimeSecs {
		return nil, fmt.Errorf("exp value is too far in the future: %s", tokenBytes)
	}
	latest := token.Expires + clockSkewSecs
	if now > latest {
		return nil, fmt.Errorf("Token used too late, %d > %d: %s", now, latest, tokenBytes)
	}

	return &token, nil
}

// verifyParsedToken performs further verification of a parsed JWT token and
// checks for the validity of Issuer, Audience, ClientID and Email fields.
// 
// Returns nil if token passes verification and can be accepted as indicated
// by audiences and clientIDs args.
var verifyParsedToken = func(cp CertProvider, token signedJWT, audiences []string, clientIDs []string) bool {
	// Verify the issuer.
	if token.Issuer != cp.Issuer() {
		return fmt.Errorf("Issuer was not valid: %s", token.Issuer)
	}

	// Check audiences.
	if token.Audience == "" {
		return fmt.Errorf("Invalid aud value in token")
	}

	if token.ClientID == "" {
		return fmt.Errorf("Invalid azp value in token")
	}

	// This is only needed if Audience and ClientID differ, which (currently) only
	// happens on Android. In the case they are equal, we only need the ClientID to
	// be in the listed of accepted Client IDs.
	if token.ClientID != token.Audience && !contains(audiences, token.Audience) {
		return fmt.Errorf("Audience not allowed: %s", token.Audience)
	}

	// Check allowed client IDs.
	if len(clientIDs) == 0 {
		return fmt.Errorf("No allowed client IDs specified. ID token cannot be verified.")
	} else if !contains(clientIDs, token.ClientID) {
		return fmt.Errorf("Client ID is not allowed: %s", token.ClientID)
	}

	if token.Email == "" {
		return fmt.Errorf("Invalid email value in token")
	}

	return nil
}

// currentIDTokenUser returns User object if provided JWT token
// was successfully decoded and passed all verifications.
// 
// Currently, only Email field will be set in case of success.
func currentIDTokenUser(cp CertProvider, jwt string, audiences []string, clientIDs []string, now int64) (*User, error) {
	parsedToken, err := verifySignedJwt(cp, jwt, now)
	if err != nil {
		return nil, err
	}

	err = verifyParsedToken(cp, *parsedToken, audiences, clientIDs)
	if err == nil {
		return &JwtUser{parsedToken.Email}, nil
	}

	return nil, errors.New("No ID token user found.")
}

// CurrentBearerTokenScope compares given scopes and clientIDs with those
// supported by the provider.
// 
// Both scopes and clientIDs args must have at least one element.
// 
// Returns a single scope (one of provided scopes) if the two conditions are met:
//   - it is supported by the provider
//   - client ID on that scope matches one of clientIDs in the args
func CurrentBearerTokenScope(p Provider, scopes []string, clientIDs []string) (string, error) {
	for _, scope := range scopes {
		clientID, err := p.CurrentOAuthClientID(scope)
		if err != nil {
			continue
		}

		for _, id := range clientIDs {
			if id == clientID {
				return scope, nil
			}
		}
		// If none of the client IDs matches, return nil
		return "", errors.New("Mismatched Client ID")
	}
	return "", errors.New("No valid scope")
}

// CurrentBearerTokenUser returns a user associated with the request which is
// expected to have a Bearer token.
// 
// Both scopes and clientIDs must have at least one element.
// 
// Returns an error if the client did not make a valid request, or none of
// clientIDs are allowed to make requests, or user did not authorize any of
// the scopes.
func CurrentBearerTokenUser(p Provider, scopes []string, clientIDs []string) (*User, error) {
	scope, err := CurrentBearerTokenScope(p, scopes, clientIDs)
	if err != nil {
		return nil, err
	}

	return p.CurrentOAuthUser(scope)
}

// CurrentUser checks for both JWT and Bearer tokens.
// 
// It first tries to decode and verify JWT token (if conditions are met)
// and falls back to Bearer token.
// 
// NOTE: Currently, returned user will have only Email field set when JWT is used.
func CurrentUser(req *http.Request, scopes []string, audiences []string, clientIDs []string) (*User, error) {
	if len(authProviders) == 0 {
		return nil, errors.New("No authentication providers registered.")
	}

	// The user hasn't provided any information to allow us to parse either
	// an ID token or a Bearer token.
	if len(scopes) == 0 && len(audiences) == 0 && len(clientIDs) == 0 {
		return nil, errors.New("No client ID or scope info provided.")
	}

	token := GetToken(req)
	if token == "" {
		return nil, errors.New("No token in the current context.")
	}

	for _, p := range authProviders {
		// If the only scope is the email scope, check an ID token. Alternatively,
		// we could check if token starts with "ya29." or "1/" to decide that it
		// is a Bearer token. This is what is done in Java.
		cp, ok := p.(CertProvider)
		if ok && len(scopes) == 1 /*&& scopes[0] == EmailScope*/ && len(clientIDs) > 0 {
			log.Printf("Checking %s for ID token.", cp.Issuer())
			now := currentUTC().Unix()
			u, err := currentIDTokenUser(cp, token, audiences, clientIDs, now)
			// Only return in case of success, else pass along and try
			// parsing Bearer token.
			if err == nil {
				return u, err
			}
		}
	}

	log.Println("Checking for Bearer token.")
	for _, p := range authProviders {
		u, err := CurrentBearerTokenUser(p, scopes, clientIDs)
		if err != nil {
			return u, err
		} else if u != nil {
			return u, nil
		}
	}
	return nil, nil
}

func AddAuthProvider(p Provider) {
	if authProviders == nil {
		authProviders = []Provider{p}
	} else {
		authProviders = append(authProviders, p)
	}
}

func ClearAuthProviders() {
	authProviders = make([]Provider, 0)
}
