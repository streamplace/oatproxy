package oatproxy

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type OATProxy struct {
	createOAuthSession  func(id string, session *OAuthSession) error
	updateOAuthSession  func(id string, session *OAuthSession) error
	userGetOAuthSession func(id string) (*OAuthSession, error)
	lock                func(id string) (func(), error)
	Echo                *echo.Echo
	host                string
	scope               string
	upstreamJWK         jwk.Key
	downstreamJWK       jwk.Key
	slog                *slog.Logger
	clientMetadata      *OAuthClientMetadata
	defaultPDS          string
}

type Config struct {
	CreateOAuthSession func(id string, session *OAuthSession) error
	UpdateOAuthSession func(id string, session *OAuthSession) error
	GetOAuthSession    func(id string) (*OAuthSession, error)
	// Lock on the given key, return a function to unlock. If not provided, OATProxy will use a local lock,
	// but you'll run into trouble with multiple nodes attempting to refresh the same session at the same time.
	Lock           func(id string) (func(), error)
	Host           string
	Scope          string
	UpstreamJWK    jwk.Key
	DownstreamJWK  jwk.Key
	Slog           *slog.Logger
	ClientMetadata *OAuthClientMetadata
	DefaultPDS     string
}

func New(conf *Config) *OATProxy {
	e := echo.New()
	mySlog := conf.Slog
	if mySlog == nil {
		mySlog = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	o := &OATProxy{
		createOAuthSession:  conf.CreateOAuthSession,
		updateOAuthSession:  conf.UpdateOAuthSession,
		userGetOAuthSession: conf.GetOAuthSession,
		Echo:                e,
		host:                conf.Host,
		scope:               conf.Scope,
		upstreamJWK:         conf.UpstreamJWK,
		downstreamJWK:       conf.DownstreamJWK,
		slog:                mySlog,
		clientMetadata:      conf.ClientMetadata,
		defaultPDS:          conf.DefaultPDS,
	}
	if conf.Lock != nil {
		o.lock = conf.Lock
	} else {
		locks := NewNamedLocks()
		o.lock = func(id string) (func(), error) {
			lock := locks.GetLock(id)
			lock.Lock()
			return func() {
				lock.Unlock()
			}, nil
		}
	}

	o.Echo.GET("/.well-known/oauth-authorization-server", o.HandleOAuthAuthorizationServer)
	o.Echo.GET("/.well-known/oauth-protected-resource", o.HandleOAuthProtectedResource)
	o.Echo.GET("/xrpc/com.atproto.identity.resolveHandle", HandleComAtprotoIdentityResolveHandle)
	o.Echo.POST("/oauth/par", o.HandleOAuthPAR)
	o.Echo.GET("/oauth/authorize", o.HandleOAuthAuthorize)
	o.Echo.GET("/oauth/return", o.HandleOAuthReturn)
	o.Echo.POST("/oauth/token", o.DPoPNonceMiddleware(o.HandleOAuthToken))
	o.Echo.POST("/oauth/revoke", o.DPoPNonceMiddleware(o.HandleOAuthRevoke))
	o.Echo.GET("/oauth/upstream/client-metadata.json", o.HandleClientMetadataUpstream)
	o.Echo.GET("/oauth/upstream/jwks.json", o.HandleJwksUpstream)
	o.Echo.GET("/oauth/downstream/client-metadata.json", o.HandleClientMetadataDownstream)
	o.Echo.Any("/xrpc/*", o.OAuthMiddleware(o.HandleWildcard))
	o.Echo.Use(o.ErrorHandlingMiddleware)
	return o
}

func (o *OATProxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // todo: ehhhhhhhhhhhh
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,DPoP")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Expose-Headers", "DPoP-Nonce")
		o.Echo.ServeHTTP(w, r)
	})
}
