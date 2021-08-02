// Package jwt provides Json-Web-Token authentication for the go-json-rest framework
package jwt

import (
	"fmt"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/golang-jwt/jwt"

	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// JWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userId is made available as
// request.Env["REMOTE_USER"].(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type JWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on userId and
	// password. Returns the Subject to set in claims on success and must return true on success, false on failure. Required.
	Authenticator func(ctx context.Context, userId string, password string) (string, bool)

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(ctx context.Context, userId string, request *rest.Request) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via request.Env["JWT_PAYLOAD"].
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(ctx context.Context, userId string) map[string]interface{}

	// Debug adds a bit of debug when the middleware rejects request with unauthorized
	// Only use while developing as it leaks details that can potentially be abused by an attacker
	Debug bool
}

// MiddlewareFunc makes JWTMiddleware implement the Middleware interface.
func (mw *JWTMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {

	if mw.Realm == "" {
		log.Fatal("Realm is required")
	}
	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}
	if mw.Key == nil {
		log.Fatal("Key required")
	}
	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}
	if mw.Authenticator == nil {
		log.Fatal("Authenticator is required")
	}
	if mw.Authorizator == nil {
		mw.Authorizator = func(ctx context.Context, userId string, request *rest.Request) bool {
			return true
		}
	}

	return func(writer rest.ResponseWriter, request *rest.Request) { mw.middlewareImpl(writer, request, handler) }
}

func (mw *JWTMiddleware) middlewareImpl(writer rest.ResponseWriter, request *rest.Request, handler rest.HandlerFunc) {
	token, err := mw.parseToken(request)

	if err != nil {
		mw.unauthorized(writer, "parseToken fail: "+err.Error())
		return
	}

	claims, ok := token.Claims.(*RestClaims)
	if !ok {
		mw.unauthorized(writer, fmt.Sprintf("Claim could not be cast from: %T\n%+v", token.Claims, token.Claims))
		return
	}

	subject := claims.Subject
	if subject == "" {
		mw.unauthorized(writer, "Subject empty")
		return
	}

	request.Env["REMOTE_USER"] = subject
	request.Env["JWT_PAYLOAD"] = claims
	ctx := request.Context()

	if !mw.Authorizator(ctx, subject, request) {
		mw.unauthorized(writer, "Authorizer rejected request")
		return
	}

	handler(writer, request)
}

// ExtractClaims allows to retrieve the payload
func ExtractClaims(request *rest.Request) *RestClaims {
	if request.Env["JWT_PAYLOAD"] == nil {
		return nil
	}
	return request.Env["JWT_PAYLOAD"].(*RestClaims)
}

type loginResponse struct {
	Token  string     `json:"token"`
	Claims RestClaims `json:"claims"`
}

type login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RestClaims struct {
	jwt.StandardClaims
	OriginalIssuedAt int64                  `json:"orig_iat,omitempty"`
	RefreshUntil     int64                  `json:"refresh_until,omitempty"`
	Custom           map[string]interface{} `json:"custom,omitempty"`
}

func (rc RestClaims) Valid() error {
	if err := rc.StandardClaims.Valid(); err != nil {
		return err
	}
	return nil
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) LoginHandler(writer rest.ResponseWriter, request *rest.Request) {
	loginVals := login{}
	err := request.DecodeJsonPayload(&loginVals)

	if err != nil {
		mw.unauthorized(writer, "Could not decode login values")
		return
	}

	ctx := request.Context()
	subject, success := mw.Authenticator(ctx, loginVals.Username, loginVals.Password)
	if !success {
		mw.unauthorized(writer, "Authentication failed")
		return
	}

	// Build the claims
	now := time.Now()
	claims := RestClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   subject,
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			ExpiresAt: now.Add(mw.Timeout).Unix(),
		},
	}

	if mw.PayloadFunc != nil {
		claims.Custom = make(map[string]interface{})
		for key, value := range mw.PayloadFunc(ctx, loginVals.Username) {
			claims.Custom[key] = value
		}
	}

	if mw.MaxRefresh != 0 {
		orgIssuedAt := time.Now()
		claims.OriginalIssuedAt = orgIssuedAt.Unix()
		claims.RefreshUntil = orgIssuedAt.Add(mw.MaxRefresh).Unix()
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(mw.SigningAlgorithm), claims)

	tokenString, err := token.SignedString(mw.Key)

	if err != nil {
		mw.unauthorized(writer, fmt.Sprintf("Could not sign: %v", err))
		return
	}

	writer.WriteJson(loginResponse{
		Token:  tokenString,
		Claims: claims,
	})
}

func (mw *JWTMiddleware) parseToken(request *rest.Request) (*jwt.Token, error) {
	authHeader := request.Header.Get("Authorization")

	if authHeader == "" {
		return nil, errors.New("Auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid auth header")
	}

	return jwt.ParseWithClaims(
		parts[1],
		&RestClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if jwt.GetSigningMethod(mw.SigningAlgorithm) != token.Method {
				return nil, errors.New("Invalid signing algorithm")
			}
			return mw.Key, nil
		})
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the JWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) RefreshHandler(writer rest.ResponseWriter, request *rest.Request) {
	token, err := mw.parseToken(request)

	// Token should be valid anyway as the RefreshHandler is authed
	if err != nil {
		mw.unauthorized(writer, "JWT not valid, not allowing refresh")
		return
	}

	claims, ok := token.Claims.(*RestClaims)
	if !ok {
		mw.unauthorized(writer, fmt.Sprintf("Claims of unexpected type: %T", token.Claims))
		return
	}
	origIat := claims.OriginalIssuedAt
	if origIat < time.Now().Add(-mw.MaxRefresh).Unix() {
		mw.unauthorized(writer, "Max refresh exceeded")
		return
	}

	// Update a few fields but leave rest as-is
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = earliestTime(time.Now().Add(mw.Timeout).Unix(), origIat+int64(mw.MaxRefresh.Seconds()))

	newToken := jwt.NewWithClaims(jwt.GetSigningMethod(mw.SigningAlgorithm), claims)
	tokenString, err := newToken.SignedString(mw.Key)
	if err != nil {
		mw.unauthorized(writer, "Unable to sign token")
		return
	}
	writer.WriteJson(loginResponse{
		Token:  tokenString,
		Claims: *claims,
	})
}

func (mw *JWTMiddleware) unauthorized(writer rest.ResponseWriter, debugReason string) {
	writer.Header().Set("WWW-Authenticate", "JWT realm="+mw.Realm)
	if mw.Debug {
		writer.Header().Set("X-Unauthorized-Reason", fmt.Sprintf(debugReason))
	}
	rest.Error(writer, "Not Authorized", http.StatusUnauthorized)
}

func earliestTime(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
