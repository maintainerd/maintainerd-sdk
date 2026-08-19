# maintainerd-sdk

The **client SDK** for maintainerd — the one library external apps and
maintainerd's own services import to **call** maintainerd services (the
`aws-sdk-go` / `boto3` analog). It wires typed service clients, attaches
identity, and verifies system-Auth (IAM) tokens.

## What "SDK" means here (and what it doesn't)

There are two distinct concerns; keep them separate:

1. **Client SDK — this repo.** How apps *call* services: `sdk.Runtime.Run(...)`,
   `sdk.Core.PullWork(...)`, `sdk.Auth.Verify(token)`. Handles connections,
   **credentials (the IAM token — AWS SigV4's role)**, and typed results. Used by
   external apps *and* by maintainerd services calling each other.
2. **Service kit — its own repo, [`maintainerd-kit`](https://github.com/maintainerd/maintainerd-kit)
   (`github.com/maintainerd/kit`).** The DRY *server-side* framework services
   share so they stop copy-pasting: config, logging, health, graceful shutdown,
   server bootstrap, the auth **PEP** middleware (`kit/authz`), the secret
   provider, and the setup/controller pattern. Split out of this repo because an
   SDK and a service framework are different products with different consumers
   and release cadences. This repo (the sdk) provides the token **verifier**
   (`sdk/auth`); the kit provides the **middleware** that uses it.

## Client SDK

```go
client, _ := sdk.New(ctx, sdk.Config{
    RuntimeAddr: "localhost:9090",           // maintainerd-docker
    CoreAddr:    "localhost:8081",           // maintainerd-core
    AuthJWKSURL: "https://auth.local/.well-known/jwks.json",
    Credentials: sdk.StaticToken(serviceToken), // attached to every call
})
defer client.Close()

id, _ := client.Runtime.Run(ctx, runtime.Spec{Image: "nginx:alpine", Name: "web"})
work, _ := client.Core.PullWork(ctx, agentUUID, 10)
```

### Identity — the IAM plumbing

- **Callers attach a token** via `Credentials` (the SigV4 analog). Under
  maintainerd, that's a **system-Auth (IAM)** token; standalone, a service or
  end-user token.
- **Callees verify** with `client.Auth` (or `auth.Verifier`): a JWKS/JWT check
  against Auth's public keys — the **PEP** that makes "attached services are
  governed by system Auth" real. It needs only Auth's JWKS URL, never the Auth
  codebase.

```go
// protect an HTTP surface with system-Auth
mux.Handle("/api/", client.Auth.Middleware(apiHandler))
```

## Packages

- `sdk` — the aggregate `Client`, `Config`, `Credentials`
- `sdk/runtime` — client for maintainerd-docker `RuntimeService`
- `sdk/core` — client for maintainerd-core `AgentGateway`
- `sdk/auth` — system-Auth (IAM) token verification + HTTP middleware

## Multi-repo note

The service clients wrap each service's generated stubs, consumed via local
module replaces (see `go.mod`) while the suite develops side by side. A Go
workspace / published modules replace this for release.
