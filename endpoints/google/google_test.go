package google

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"fmt"
)

const (
	tokeinfoUserId = "12345"
	tokeinfoEmail  = "dude@gmail.com"
)

var (
	tokeninfoValid = []byte(`{
		"issued_to": "my-client-id",
		"audience": "my-client-id",
		"user_id": "` + tokeinfoUserId + `",
		"scope": "scope.one scope.two",
		"expires_in": 3600,
		"email": "` + tokeinfoEmail + `",
		"verified_email": true,
		"access_type": "online"
	}`)
	tokeninfoUnverified = []byte(`{
		"expires_in": 3600,
		"verified_email": false,
		"email": "user@example.org"
	}`)
	// is this even possible for email to be "" and verified == true?
	tokeninfoInvalidEmail = []byte(`{
		"expires_in": 3600,
		"verified_email": true,
		"email": ""
	}`)
	tokeninfoError = []byte(`{
		"error_description": "Invalid value"
	}`)
)

func TestGoogleProviderCurrentOAuthClientID(t *testing.T) {
	const token = "some_token"

	type test struct {
		token, scope, clientId string
		httpStatus             int32
		content                []byte
		fetchErr               error
	}

	var currTT *test

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := r.URL.Query().Get("access_token")
		if at != token {
			t.Errorf("expected: %s actual: %s", token, at)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(currTT.httpStatus)
		fmt.Fprintln(w, currTT.content)
	}))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	save := tokeninfoEndpointUrl
	defer func() {
		tokeninfoEndpointUrl = save
	}()
	tokeninfoEndpointUrl = ts.URL

	tts := []*test{
		// token, scope, clientId, httpStatus, content, fetchErr
		{token, "scope.one", "my-client-id", 200, tokeninfoValid, nil},
		{token, "scope.two", "my-client-id", 200, tokeninfoValid, nil},
		{token, "scope.one", "", 200, tokeninfoUnverified, nil},
		{token, "scope.one", "", 200, tokeninfoInvalidEmail, nil},
		{token, "scope.one", "", 401, tokeninfoError, nil},
		{token, "invalid.scope", "", 200, tokeninfoValid, nil},
		{token, "scope.one", "", 400, []byte("{}"), nil},
		{token, "scope.one", "", 200, []byte(""), nil},
//		{token, "scope.one", "", -1, nil, errors.New("Fake urlfetch error")},
		{"", "scope.one", "", 200, tokeninfoValid, nil},
	}

	p := NewGoogleProvider()
	for i, tt := range tts {
		currTT = tt
		r.Header.Set("Authorization", "bearer "+tt.token)
		id, err := p.CurrentOAuthClientID(r, tt.scope)
		switch {
		case err != nil && tt.clientId != "":
			t.Errorf("%d: expected %q, got error %v", i, tt.clientId, err)
		case err == nil && tt.clientId == "":
			t.Errorf("%d: expected error, got %q", i, id)
		case err == nil && id != tt.clientId:
			t.Errorf("%d: expected %q, got %q", i, tt.clientId, id)
		}
	}
}

func TestGoogleProviderCurrentOAuthUser(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintln(w, tokeninfoValid)
	}))
	defer ts.Close()

	r, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	r.Header.Set("Authorization", "bearer some_token")

	save := tokeninfoEndpointUrl
	defer func() {
		tokeninfoEndpointUrl = save
	}()
	tokeninfoEndpointUrl = ts.URL

	p := NewGoogleProvider()
	user, err := p.CurrentOAuthUser(r, "scope.one")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user.Email() != tokeinfoEmail {
		t.Errorf("expected email %q, got %q", tokeinfoEmail, user.Email())
	}
}
