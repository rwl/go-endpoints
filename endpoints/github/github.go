
package github

import "time"

const checkUri = " https://api.github.com/applications/:client_id/tokens/:access_token"

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
	Id int `json:"id"`
	Url string `json:"url"`
	Scopes []string `json:"scopes"`
	Token string `json:"token"`
	App Application `json:"app"`
	Note string `json:"note"`
	NoteUrl string `json:"note_url"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedAt time.Time `json:"created_at"`
	User GithubUser `json:"user"`
}

type Application struct {
	Url string `json:"url"`
	Name string `json:"name"`
	ClientId string `json:"client_id"`
}

type GithubUser struct {
	Id int `json:"id"`
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
