
package github

import (
	"time"
	"log"
	"net/http"
	"encoding/json"
	"fmt"
	"errors"
	"github.com/rwl/go-endpoints/endpoints"
)

const checkUri = " https://api.github.com/applications/%s/tokens/%s"

const (
	// (no scope) - Public read-only access (includes public user profile info, public repo info, and gists)
	UserScope = "user" // Read/write access to profile info only. Note: this scope includes user:email and user:follow.
	EmailScope = "user:email" // Read access to a user’s email addresses.
	FollowScope = "user:follow" // Access to follow or unfollow other users.
	PublicRepoScope = "public_repo" // Read/write access to public repos and organizations.
	RepoScope = "repo" // Read/write access to public and private repos and organizations.
	StatusScope  = "repo:status" // Read/write access to public and private repository commit statuses. This scope is only necessary to grant other users or services access to private repository commit statuses without granting access to the code. The repo and public_repo scopes already include access to commit status for private and public repositories, respectively.
	DeleteRepoScope = "delete_repo" // Delete access to adminable repositories.
	NotificationsScope = "notifications" // Read access to a user’s notifications. repo is accepted too.
	GistScope = "gist" // Write access to gists.
)

type TokenInfo struct {
	Id int64 `json:"id"`
	Url string `json:"url"`
	Scopes []string `json:"scopes"`
	Token string `json:"token"`
	App *Application `json:"app"`
	Note string `json:"note"`
	NoteUrl string `json:"note_url"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedAt time.Time `json:"created_at"`
	User *GithubUser `json:"user"`
}

type Application struct {
	Url string `json:"url"`
	Name string `json:"name"`
	ClientId string `json:"client_id"`
}

type GithubUser struct {
	Id int64 `json:"id"`
	Login string `json:"login"`
	AvatarUrl string `json:"avatar_url`
	GravatarId string `json:"gravatar_id"`
	Url string `json:"url"`
	HtmlUrl string `json:"html_url"`
	FollowersUrl string `json:"followers_url"`
	FollowingUrl string `json:"following_url"`
	GistsUrl string `json:"gists_url"`
	StarredUrl string `json:"starred_url"`
	SubscriptionsUrl string `json:"subsriptions_url"`
	OrganizationsUrl string `json:"organizations_url"`
	ReposUrl string `json:"repos_url"`
	EventsUrl string `json:"events_url"`
	ReceivedEventsUrl string `json:"received_events_url"`
	Type string `json:"type"`
	SiteAdmin bool `json:"site_admin"`
}

func (u *GithubUser) UserId() string {
	return u.Id
}

func (u *GithubUser) Email() string {
	return ""
}

func (u *GithubUser) AuthDomain() string {
	return "api.github.com"
}

func fetchTokeninfo(token, clientId string) (*TokenInfo, error) {
	url := fmt.Sprintf(checkUri, clientId, token)
	log.Printf("Fetching token info from %q", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ti := &TokenInfo{}
	if err = json.NewDecoder(resp.Body).Decode(ti); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error fetching tokeninfo (status %d)", resp.StatusCode)
	}

	return ti, err
}

func getScopedTokeninfo(req *http.Request, scope, clientId string) (*TokenInfo, error) {
	token := endpoints.GetToken(req)
	if token == "" {
		return nil, errors.New("No token found")
	}
	ti, err := fetchTokeninfo(token, clientId)
	if err != nil {
		return nil, err
	}
	for _, s := range ti.Scopes {
		if s == scope {
			return ti, nil
		}
	}
	return nil, fmt.Errorf("No scope matches: expected one of %q, got %q",
		ti.Scope, scope)
}

// A provider that uses the Github API to validate bearer tokens.
type GithubProvider struct {
	clientId string
}

func NewGithubProvider(clientId string) *GithubProvider {
	return &GithubProvider{clientId}
}

// CurrentOAuthClientID returns a clientId associated with the scope.
func (p *GithubProvider) CurrentOAuthClientID(req *http.Request, scope string) (string, error) {
	ti, err := getScopedTokeninfo(req, scope, p.clientId)
	if err != nil {
		return "", err
	}
	if ti.App == nil {
		return "", err
	}
	return ti.App.ClientId, nil
}

// CurrentOAuthUser returns a user associated with the request in context.
func (p *GithubProvider) CurrentOAuthUser(req *http.Request, scope string) (*endpoints.User, error) {
	ti, err := getScopedTokeninfo(req, scope, p.clientId)
	if err != nil {
		return nil, err
	}
	return ti.User, nil
}
