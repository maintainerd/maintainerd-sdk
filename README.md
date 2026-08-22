# maintainerd-sdk

The **client SDK** for maintainerd — the one library external apps and
maintainerd's own services import to **call** maintainerd's **product services**
(the `aws-sdk-go` / `boto3` analog). It wires typed service clients, attaches
identity, and verifies system-Auth (IAM) tokens.

## Scope — product services, not the control plane

The SDK exposes the services an app **consumes** — auth (verify), secret, and
future ones (storage, database, …) — exactly the AWS line: `aws-sdk-go` ships
S3/DynamoDB clients, **not** AWS's internal control plane. So the SDK does **not**
contain core's AgentGateway, the docker runtime, orchestration, or setup — those
are internal wiring that lives in the consuming service (e.g. the agent) or in
the internal [`maintainerd-kit`](https://github.com/maintainerd/maintainerd-kit),
never here.

Two distinct concerns, kept separate:

1. **Client SDK — this repo.** How apps *call* product services and authenticate.
   Used by external apps *and* by maintainerd services.
2. **Service kit — [`maintainerd-kit`](https://github.com/maintainerd/maintainerd-kit)
   (`github.com/maintainerd/kit`).** The DRY *server-side* framework (config,
   logging, server bootstrap, the auth **PEP** middleware, secret provider, setup)
   — how you *build & operate* a service. Different product, different consumers.

## Usage

```go
client, _ := sdk.New(ctx, sdk.Config{
    SecretAddr:  "localhost:9092",             // maintainerd-secret (a product service)
    AuthJWKSURL: "https://auth.local/.well-known/jwks.json",
    Credentials: sdk.StaticToken(serviceToken), // attached to every call
})
defer client.Close()

val, _ := client.Secret.Get(ctx, "db/password")
```

### Identity — verifying and authenticating

- **Callees verify** with `client.Auth` (or `auth.Verifier`): a JWKS/JWT check
  against Auth's public keys. It needs only Auth's JWKS URL, never the Auth
  codebase. `Claims.HasScope` + `auth.RequireScope` authorize, not just
  authenticate.
- **Callers attach a token** via `Credentials` (the SigV4 analog):
  - `StaticToken` / `Anonymous`
  - `ClientCredentials` — OAuth2 client_credentials (a secret-holding client)
  - `PrivateKeyJWT` — RFC 7523 client assertion (the client keeps the private
    key; Auth holds only the public JWKS)
- **`auth.Discover`** resolves Auth's endpoints from its issuer (no hardcoding).

```go
// protect an HTTP surface with system-Auth
mux.Handle("/api/", client.Auth.Middleware(apiHandler))
```

### Authorization — MRN-aware route enforcement

`sdk/auth` answers *"is this token valid, and does it carry scope X"*. `sdk/authz`
answers the question that actually gates a resource: **may THIS principal perform
THIS action on THIS resource?**

Auth is the policy **authority** (PDP); **every service enforces authorization
itself** (PEP) — a service must run standalone with no gateway in front of it, only
the service knows its own resource ownership, and traffic arrives from peers and
agents that never passed a gateway. `sdk/authz` is that enforcement point, written
once here so every service *and* every third-party resource server guards routes
identically.

Two layers, two different questions:

1. **The surface guard** (`Guard.Middleware`, `Guard.UnaryInterceptor`,
   `Guard.StreamInterceptor`) — is the caller authenticated, and is this surface one
   the service decided a permission for? The route/method `Map` doubles as an
   **allowlist**: an unmapped surface is denied even to a valid token, so adding a
   route without deciding its permission fails closed.
2. **The operation check** (`Principal.Allows`) — MRN-level, in the handler, against
   the target resource. This is what makes "may read staging, must not read prod"
   expressible at all.

```go
perms := authz.Map{
    Prefix: "/api/v1/",
    Routes: map[string]authz.Perms{
        "projects": {Read: "secret:ReadMetadata", Write: "secret:ManageProject"},
        "secrets":  {Read: "secret:ReadMetadata", Write: "secret:ReadMetadata"},
    },
    Methods:              map[string]string{"/…/SecretService/Reveal": "secret:GetSecret"},
    OperationPermissions: []string{"secret:GetSecret", "secret:PutSecret"},
    BlanketActions:       []string{"secret:Admin"},
    ExemptPaths:          []string{"/healthz", "/api/v1/setup"},
}

guard, err := authz.Resolve(ctx, authz.Config{
    JWKSURL: jwksURL, Issuer: issuer, Audience: audience,
    Development: appEnv == "development",
    Service:     "secret",
}, perms)
guard.LogBanner()

mux.Handle("/api/v1/", guard.Middleware(apiHandler))
grpc.NewServer(
    grpc.UnaryInterceptor(guard.UnaryInterceptor()),
    grpc.StreamInterceptor(guard.StreamInterceptor()),
)

// in a handler — the check that matters
p, _ := authz.FromContext(r.Context())
if !p.Allows("secret:GetSecret", targetMRN) { /* 403 */ }
```

**The grant grammar.** One entry of a token's `scope` / `permissions` claim:

| Form | Meaning |
|---|---|
| `secret:ReadMetadata` | the action, **service-wide** (equivalent to `=mrn:secret:*:*:*`) |
| `secret:GetSecret=mrn:secret:acme:billing:secret/staging/*` | the action, **narrowed** to the MRN pattern |

Both claim shapes Auth can mint are read — the space-separated `scope` string *and*
the `permissions` array. Reading only one silently authorizes half the fleet.

**Registration cannot drift from enforcement.** `Map.DeclaredPermissions()` derives
the exact permission list setup registers in Auth from the same map the guard
enforces. Hand-listing it at the registration site is how you get a silent, total API
outage — the guard demands a permission that exists nowhere in Auth, so no token can
carry it and every call 403s.

**The mode ladder** (`authz.Resolve`) is fail-closed: fully configured → `Enforced`;
unconfigured in development → `DevOpen` with a loud banner naming every disabled
guard; unconfigured anywhere else → `Unavailable` (503 / `codes.Unavailable`). There
is no fourth rung where a partial configuration guesses.

## Packages

- `sdk` — the aggregate `Client`, `Config`, `Credentials`, token sources
  (`StaticToken`, `Anonymous`, `ClientCredentials`, `PrivateKeyJWT`)
- `sdk/secret` — client for maintainerd-secret `SecretService`
- `sdk/auth` — token verification, scope checks, HTTP middleware, OIDC discovery
- `sdk/authz` — MRN-aware permission enforcement: the grant grammar, the
  route/method allowlist, HTTP middleware + gRPC interceptors, the
  `Enforced`/`DevOpen`/`Unavailable` mode ladder, and `DeclaredPermissions()`
- `sdk/mrn` — the `mrn:<service>:<tenant>:<project>:<resource-path>` parser and
  segment-aware matcher (wildcards never span a colon, so a grant for tenant `acme`
  can never reach `acmecorp`). stdlib-only

`sdk/authz` is **additive**: `auth.Verifier`, `auth.Claims.HasScope` and
`auth.RequireScope` are unchanged and remain correct for surfaces whose only question
is "does this token carry scope X". Plug an existing verifier into the new guard with
one call — `authz.SDKVerify(v)`.

## Multi-repo note

The service clients wrap each service's generated stubs, consumed via local
module replaces (see `go.mod`) while the suite develops side by side. A Go
workspace / published modules replace this for release.
