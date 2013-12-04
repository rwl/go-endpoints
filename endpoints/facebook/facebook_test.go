
package facebook

const (
	appId = "138483919580948"
	userId = "1207059"
)

var validDebug = []byte(`{
	"data": {
		"app_id": ` + appId + `,
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
		"user_id": ` + userId + `
	}
}`)

var debugError = []byte(`{
	"error": {
		"message": "Message describing the error",
		"type": "OAuthException",
		"code": 190 ,
		"error_subcode": 460
	}
}`)

var validUser = `{
	"id": ` + userId + `
	"username": "jsmith",
	"first_name": "John",
	"last_name": "Smith",
	"verified": true
}`
