// Cacheing implementation of Provider interface.

package appengine

import (
	"net/http"
	"sync"
	"encoding/json"

	"github.com/rwl/go-endpoints/endpoints"
	"github.com/rwl/go-endpoints/endpoints/google"

	"appengine"
	"appengine/user"
	"appengine/memcache"
	"appengine/urlfetch"

	pb "appengine_internal/user"
	"time"
)

var certNamespace = "__verify_jwt"

type CachingProvider struct {
	ctx *appengine.Context

	// map keys are scopes
	oauthResponseCache map[string]*pb.GetOAuthUserResponse
	// mutex for oauthResponseCache
	sync.Mutex
}

func NewCachingProvider(context *appengine.Context) *CachingProvider {
	return &CachingProvider{
		context,
		map[string]*pb.GetOAuthUserResponse{},
		sync.Mutex{},
	}
}

func (p *CachingProvider) SetContext(context *appengine.Context) {
	p.ctx = context
}

// populateOAuthResponse updates (overwrites) OAuth user data associated with
// this request and the given scope.
func populateOAuthResponse(p *CachingProvider, scope string) error {
	// Only one scope should be cached at once, so we just destroy the cache
	p.oauthResponseCache = map[string]*pb.GetOAuthUserResponse{}

	req := &pb.GetOAuthUserRequest{Scope: &scope}
	res := &pb.GetOAuthUserResponse{}

	err := p.ctx.Call("user", "GetOAuthUser", req, res, nil)
	if err != nil {
		return err
	}

	p.oauthResponseCache[scope] = res
	return nil
}

func getOAuthResponse(p *CachingProvider, scope string) (*pb.GetOAuthUserResponse, error) {
	res, ok := p.oauthResponseCache[scope]

	if !ok {
		p.Lock()
		defer p.Unlock()
		if err := populateOAuthResponse(c, scope); err != nil {
			return nil, err
		}
		res = p.oauthResponseCache[scope]
	}

	return res, nil
}

// CurrentOAuthClientID returns a clientId associated with the scope.
func (p *CachingProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
	res, err := getOAuthResponse(p, scope)
	if err != nil {
		return "", err
	}
	return res.GetClientId(), nil
}

// CurrentOAuthUser returns a user of this request for the given scope.
// It caches OAuth info at the first call for future invocations.
// 
// Returns an error if data for this scope is not available.
func (p *CachingProvider) CurrentOAuthUser(req *http.Request, scope string) (*user.User, error) {
	res, err := getOAuthResponse(p, scope)
	if err != nil {
		return nil, err
	}

	return &user.User{
		Email:      *res.Email,
		AuthDomain: *res.AuthDomain,
		Admin:      res.GetIsAdmin(),
		ID:         *res.UserId,
	}, nil
}

func (p *CachingProvider) CachedCerts() *endpoints.CertsList {
	namespacedContext, err := appengine.Namespace(c, certNamespace)
	if err != nil {
		return nil
	}

	var certs *endpoints.CertsList

	_, err = memcache.JSON.Get(namespacedContext, DefaultCertUri, &certs)
	if err == nil {
		return certs
	}

	// Cache miss or server error.
	// If any error other than cache miss, it's proably not a good time
	// to use memcache.
	if err != memcache.ErrCacheMiss {
		p.ctx.Debugf(err.Error())
	}
}

func (p *CachingProvider) CacheCerts(certs *endpoints.CertsList, expiration time.Duration) {
	certBytes, err := json.Marshal(certs)
	if err != nil {
		p.ctx.Errorf("Error marshalling Certs to JSON: %v", err)
	}
	item := &memcache.Item{
		Key:        certUri,
		Value:      certBytes,
		Expiration: expiration,
	}
	err = memcache.Set(namespacedContext, item)
	if err != nil {
		p.ctx.Errorf("Error adding Certs to memcache: %v", err)
	}

}

func (p *CachingProvider) CertUri() string {
	return google.CertUri
}

func (p *CachingProvider) Issuer() string {
	return google.Issuer
}

func (p *CachingProvider) Client() *http.Client {
	return urlfetch.Client(p.ctx)
}
