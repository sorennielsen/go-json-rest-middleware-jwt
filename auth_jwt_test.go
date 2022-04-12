package jwt

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/golang-jwt/jwt"
)

var (
	key = []byte("secret key")
)

type DecoderToken struct {
	Token string `json:"token"`
	Error string `json:"Error"`
}

func makeClaims(username string) RestClaims {
	now := time.Now()
	claims := RestClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   username,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(),
		},
		OriginalIssuedAt: now.Unix(),
		Custom:           make(map[string]interface{}),
	}
	return claims
}

func makeTokenString(username string, key []byte) string {
	claims := makeClaims(username)
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Println(err)
		return ""
	}

	return tokenString
}

// the middleware to test
func makeAthMiddleware() *JWTMiddleware {
	return &JWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(ctx context.Context, userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "admin", true
			}
			return "", false
		},
		Authorizator: func(ctx context.Context, userId string, request *rest.Request) bool {
			if request.Method == "GET" {
				return true
			}
			return false
		},
	}
}

func TestAuthJWT(t *testing.T) {

	authMiddleware := makeAthMiddleware()

	// api for testing failure
	apiFailure := rest.NewApi()
	apiFailure.Use(authMiddleware)
	apiFailure.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		t.Logf("URL requested: %v", r.URL.Path)
		t.Error("Should never be executed")
	}))
	handler := apiFailure.MakeHandler()

	// simple request fails
	recorded := test.RunRequest(t, handler, test.MakeSimpleRequest("GET", "http://localhost/simple request fails", nil))
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// auth with right cred and wrong method fails
	wrongMethodReq := test.MakeSimpleRequest("POST", "http://localhost/auth with right cred and wrong method fails", nil)
	wrongMethodReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongMethodReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - bearer lower case
	wrongAuthFormat := test.MakeSimpleRequest("GET", "http://localhost/wrong Auth format - bearer lower case", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - no space after bearer
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/wrong Auth format - no space after bearer", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer"+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - empty auth header
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/wrong Auth format - empty auth header", nil)
	wrongAuthFormat.Header.Set("Authorization", "")
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method but wrong priv key
	wrongPrivKeyReq := test.MakeSimpleRequest("GET", "http://localhost/right credt, right method but wrong priv key", nil)
	wrongPrivKeyReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", []byte("sekret key")))
	recorded = test.RunRequest(t, handler, wrongPrivKeyReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method, right priv key but timeout
	claims := makeClaims("admin")
	claims.ExpiresAt = 1 // If zero it will be valid as "assumed not set"
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

	tokenString, _ := token.SignedString(key)

	expiredTimestampReq := test.MakeSimpleRequest("GET", "http://localhost/right credt, right method, right priv key but timeout", nil)
	expiredTimestampReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, handler, expiredTimestampReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method, right priv key but no id
	claimsNoID := makeClaims("")
	tokenNoId := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claimsNoID)
	tokenNoIdString, _ := tokenNoId.SignedString(key)

	noIDReq := test.MakeSimpleRequest("GET", "http://localhost/right credt, right method, right priv key but no id", nil)
	noIDReq.Header.Set("Authorization", "Bearer "+tokenNoIdString)
	recorded = test.RunRequest(t, handler, noIDReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credt, right method, right priv, wrong signing method on request
	claimsBadSigning := makeClaims("admin")
	tokenBadSigning := jwt.NewWithClaims(jwt.GetSigningMethod("HS384"), claimsBadSigning)
	tokenBadSigningString, _ := tokenBadSigning.SignedString(key)

	BadSigningReq := test.MakeSimpleRequest("GET", "http://localhost/right credt, right method, right priv, wrong signing method on request", nil)
	BadSigningReq.Header.Set("Authorization", "Bearer "+tokenBadSigningString)
	recorded = test.RunRequest(t, handler, BadSigningReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// api for testing success
	apiSuccess := rest.NewApi()
	apiSuccess.Use(authMiddleware)
	apiSuccess.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		if r.Env["REMOTE_USER"] == nil {
			t.Error("REMOTE_USER is nil")
		}
		user := r.Env["REMOTE_USER"].(string)
		if user != "admin" {
			t.Error("REMOTE_USER is expected to be 'admin'")
		}
		w.WriteJson(map[string]string{"Id": "123"})
	}))

	// auth with right cred and right method succeeds
	validReq := test.MakeSimpleRequest("GET", "http://localhost/auth with right cred and right method succeeds", nil)
	validReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, apiSuccess.MakeHandler(), validReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// login tests
	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// wrong login
	wrongLoginCreds := map[string]string{"username": "admin", "password": "admIn"}
	wrongLoginReq := test.MakeSimpleRequest("POST", "http://localhost/wrong login", wrongLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), wrongLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// empty login
	emptyLoginCreds := map[string]string{}
	emptyLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", emptyLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), emptyLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// correct login
	before := time.Now().Unix()
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/empty login", loginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.Parse(nToken.Token, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Errorf("Received new token with wrong signature: %v", err)
	}

	claimsCorrectLogin := newToken.Claims.(jwt.MapClaims)

	if claimsCorrectLogin["sub"] != "admin" ||
		int64(claimsCorrectLogin["exp"].(float64)) < before {
		t.Errorf("Received new token with wrong data")
	}

}

func TestRefreshFail(t *testing.T) {

	authMiddleware := makeAthMiddleware()

	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	// refresh with expired max refresh
	// the combination actually doesn't make sense but is ok for the test
	claimsUnrefreshable := makeClaims("admin")
	claimsUnrefreshable.OriginalIssuedAt = 0
	unrefreshableToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claimsUnrefreshable)
	tokenString, _ := unrefreshableToken.SignedString(key)

	unrefreshableReq := test.MakeSimpleRequest("GET", "http://localhost/TestRefreshFail", nil)
	unrefreshableReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded := test.RunRequest(t, refreshApi.MakeHandler(), unrefreshableReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()
}

func TestRefreshSuccess(t *testing.T) {

	authMiddleware := makeAthMiddleware()

	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	claimsRefreshable := makeClaims("admin")
	claimsRefreshable.ExpiresAt = time.Now().Add(time.Hour).Unix() - 1
	claimsRefreshable.OriginalIssuedAt = time.Now().Unix() - 1

	refreshableToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claimsRefreshable)
	// we need to substract one to test the case where token is being created in
	// the same second as it is checked -> < wouldn't fail
	tokenString, err := refreshableToken.SignedString(key)
	if err != nil {
		t.Errorf("Signing error: %v", err)
	}

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/TestRefreshSuccess", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded := test.RunRequest(t, refreshApi.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.ParseWithClaims(rToken.Token, &RestClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Logf("Error token: %+v, %v", rToken, recorded.Recorder.Code)
		t.Errorf("Received refreshed token with wrong signature: %v", err)
		return
	}

	claimsRefresh := refreshToken.Claims.(*RestClaims)

	if claimsRefresh.Subject != "admin" ||
		claimsRefresh.OriginalIssuedAt != claimsRefreshable.OriginalIssuedAt ||
		claimsRefresh.ExpiresAt < claimsRefreshable.ExpiresAt {
		t.Errorf("Received refreshed token with wrong data")
	}
}

func TestAuthJWTPayload(t *testing.T) {
	authMiddleware := &JWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(ctx context.Context, userId string, password string) (string, bool) {
			if userId == "admin" && password == "admin" {
				return "admin", true
			}
			return "", false
		},
		PayloadFunc: func(ctx context.Context, userId string) map[string]interface{} {
			// tests normal value
			// tests overwriting of reserved jwt values should have no effect
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
	}

	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// correct payload
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/TestAuthJWTPayload", loginCreds)
	recorded := test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.ParseWithClaims(nToken.Token, &RestClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Error("Received new token with wrong signature", err)
	}

	claims := newToken.Claims.(*RestClaims)
	if claims.Custom["testkey"].(string) != "testval" || claims.ExpiresAt == 0 {
		t.Errorf("Received new token without payload")
	}

	// correct payload after refresh
	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	claimsRefreshable := makeClaims("admin")
	claimsRefreshable.Custom["testkey"] = "testval"
	refreshableToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claimsRefreshable)
	tokenString, err := refreshableToken.SignedString(key)
	if err != nil {
		t.Errorf("Could not sign token: %v", err)
	}

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/correct payload after refresh", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.ParseWithClaims(rToken.Token, &RestClaims{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		t.Error("Received refreshed token with wrong signature", err)
	}

	claimsRefresh := refreshToken.Claims.(*RestClaims)

	if claimsRefresh.Custom["testkey"].(string) != "testval" {
		t.Errorf("Received new token without payload")
	}

	// payload is accessible in request
	payloadApi := rest.NewApi()
	payloadApi.Use(authMiddleware)
	payloadApi.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		testval := r.Env["JWT_PAYLOAD"].(*RestClaims).Custom["testkey"].(string)
		w.WriteJson(map[string]string{"testkey": testval})
	}))

	claimsPayload := makeClaims("admin")
	claimsPayload.Custom["testkey"] = "testval"
	payloadToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claimsPayload)
	payloadTokenString, _ := payloadToken.SignedString(key)

	payloadReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	payloadReq.Header.Set("Authorization", "Bearer "+payloadTokenString)
	recorded = test.RunRequest(t, payloadApi.MakeHandler(), payloadReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	payload := map[string]string{}
	test.DecodeJsonPayload(recorded.Recorder, &payload)

	if payload["testkey"] != "testval" {
		t.Errorf("Received new token without payload")
	}

}

func TestClaimsDuringAuthorization(t *testing.T) {
	authMiddleware := &JWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		PayloadFunc: func(ctx context.Context, userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(ctx context.Context, userId string, password string) (string, bool) {
			// Not testing authentication, just authorization, so always return true
			return userId, true
		},
		Authorizator: func(ctx context.Context, userId string, request *rest.Request) bool {
			jwt_claims := ExtractClaims(request)

			// Check the actual claim, set in PayloadFunc
			return (jwt_claims.Custom["testkey"] == "testval")
		},
	}

	// Simple endpoint
	endpoint := func(w rest.ResponseWriter, r *rest.Request) {
		// Dummy endpoint, output doesn't really matter, we are checking
		// the code returned
		w.WriteJson(map[string]string{"Id": "123"})
	}

	// Setup simple app structure
	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))
	loginApi.Use(&rest.IfMiddleware{
		// Only authenticate non /login requests
		Condition: func(request *rest.Request) bool {
			return request.URL.Path != "/login"
		},
		IfTrue: authMiddleware,
	})
	api_router, _ := rest.MakeRouter(
		rest.Post("/login", authMiddleware.LoginHandler),
		rest.Get("/", endpoint),
	)
	loginApi.SetApp(api_router)

	// Authenticate
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/login", loginCreds)
	recorded := test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// Decode received token, to be sent with endpoint request
	nToken := DecoderToken{}
	test.DecodeJsonPayload(recorded.Recorder, &nToken)

	// Request endpoint, triggering Authorization.
	// If we get a 200 then the claims were available in Authorizator method
	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	req.Header.Set("Authorization", "Bearer "+nToken.Token)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}
