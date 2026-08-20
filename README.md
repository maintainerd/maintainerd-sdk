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

## Packages

- `sdk` — the aggregate `Client`, `Config`, `Credentials`, token sources
  (`StaticToken`, `Anonymous`, `ClientCredentials`, `PrivateKeyJWT`)
- `sdk/secret` — client for maintainerd-secret `SecretService`
- `sdk/auth` — token verification, scope checks, HTTP middleware, OIDC discovery

## Multi-repo note

The service clients wrap each service's generated stubs, consumed via local
module replaces (see `go.mod`) while the suite develops side by side. A Go
workspace / published modules replace this for release.
