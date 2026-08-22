package authz

import (
	"context"
	"log/slog"
	"strings"

	"github.com/maintainerd/sdk/auth"
)

// The environment variables the platform standardises on for a service's link to
// Auth. They are named in Resolve's failure reason so an operator who has set two of
// the three is told which one is missing.
const (
	EnvJWKSURL  = "AUTH_JWKS_URL"
	EnvIssuer   = "AUTH_ISSUER"
	EnvAudience = "AUTH_AUDIENCE"
)

// Config is the auth wiring a service resolves from its environment at boot.
type Config struct {
	// JWKSURL, Issuer and Audience are Auth's public key endpoint and the two checks
	// that make a token THIS service's token rather than merely a well-formed one.
	// All three are required for enforcement.
	JWKSURL  string
	Issuer   string
	Audience string
	// Development permits the reduced-safety open mode. Wire it from APP_ENV, never
	// from a flag a production deployment could set.
	Development bool
	// Service names the service in banners and logs, e.g. "secret".
	Service string
	// DevOpenWarnings are extra service-specific consequences appended to the dev-open
	// banner (see Guard.DevOpenWarnings).
	DevOpenWarnings []string
}

// Resolve decides the guard posture and builds the verifier.
//
// The ladder is the whole point, and it has exactly three rungs:
//
//	fully configured             -> ModeEnforced
//	unconfigured, development    -> ModeDevOpen    (with a loud banner)
//	unconfigured, anything else  -> ModeUnavailable
//
// There is no fourth rung where a partially configured service guesses. A JWKS URL
// without an issuer or audience check is a service that accepts any token signed by
// Auth for anyone — including tokens minted for a different audience entirely — so a
// partial configuration is treated as no configuration.
//
// An error is returned ONLY when the configuration is present but unusable (the JWKS
// endpoint cannot be prepared). That is a genuine boot failure: the operator asked
// for enforcement and it cannot be provided, and silently downgrading to open or
// unavailable would either expose the service or hide a typo.
func Resolve(ctx context.Context, cfg Config, permissions Map) (Guard, error) {
	g := Guard{
		Permissions:     permissions,
		Service:         cfg.Service,
		DevOpenWarnings: cfg.DevOpenWarnings,
	}

	jwks := strings.TrimSpace(cfg.JWKSURL)
	issuer := strings.TrimSpace(cfg.Issuer)
	audience := strings.TrimSpace(cfg.Audience)

	if jwks != "" && issuer != "" && audience != "" {
		v, err := auth.NewVerifier(ctx, jwks, issuer, audience)
		if err != nil {
			return Guard{}, err
		}
		g.Mode = ModeEnforced
		g.Verify = SDKVerify(v)
		return g, nil
	}

	g.Reason = missingReason(jwks, issuer, audience)
	if cfg.Development {
		g.Mode = ModeDevOpen
		return g, nil
	}
	g.Mode = ModeUnavailable
	return g, nil
}

// missingReason names exactly which variables are absent, because "auth is not
// configured" is the least useful possible message to an operator who has set two of
// the three.
func missingReason(jwks, issuer, audience string) string {
	var missing []string
	if jwks == "" {
		missing = append(missing, EnvJWKSURL)
	}
	if issuer == "" {
		missing = append(missing, EnvIssuer)
	}
	if audience == "" {
		missing = append(missing, EnvAudience)
	}
	if len(missing) == 0 {
		return ""
	}
	return strings.Join(missing, ", ") + " not set"
}

// LogBanner announces the resolved posture at boot.
//
// The development banner names every disabled guard INDIVIDUALLY rather than saying
// "auth disabled". A one-line summary is easy to skim past in a startup log; a list
// of concrete consequences is not. This is the last warning before an unguarded
// service starts answering requests, and the intended reader is a human who has just
// changed an environment variable and is not sure what it did.
func (g Guard) LogBanner() {
	log := g.Logger
	if log == nil {
		log = slog.Default()
	}
	service := g.Service
	if service == "" {
		service = "service"
	}

	switch g.Mode {
	case ModeEnforced:
		log.Info("authorization: ENFORCED",
			"service", service,
			"mode", g.Mode.String(),
			"permissions", strings.Join(g.DeclaredPermissions(), " "))
	case ModeDevOpen:
		log.Warn("=====================================================================")
		log.Warn("AUTHORIZATION IS DISABLED — DEVELOPMENT MODE ONLY",
			"service", service, "cause", g.Reason)
		log.Warn("The following guards are OFF on this instance:")
		log.Warn("  * bearer-token authentication — requests need no credential at all")
		log.Warn("  * per-action permissions — every caller is treated as a blanket administrator")
		log.Warn("  * MRN scoping — no tenant, project or resource boundary is applied")
		for _, extra := range g.DevOpenWarnings {
			log.Warn("  * " + extra)
		}
		log.Warn("Audit rows, where written, are attributed to the subject '" + DevOpenSubject + "'.")
		log.Warn("Set " + EnvJWKSURL + ", " + EnvIssuer + " and " + EnvAudience + " to enforce.")
		log.Warn("=====================================================================")
	default:
		log.Error("authorization: UNAVAILABLE — the API is disabled",
			"service", service,
			"cause", g.Reason,
			"effect", "guarded surfaces answer 503 / Unavailable until auth is configured")
	}
}
