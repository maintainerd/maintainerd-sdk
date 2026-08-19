module github.com/maintainerd/sdk

go 1.26.6

replace github.com/maintainerd/docker => ../maintainerd-docker

replace github.com/maintainerd/core => ../maintainerd

require (
	github.com/MicahParks/keyfunc/v3 v3.8.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/maintainerd/core v0.0.0-00010101000000-000000000000
	github.com/maintainerd/docker v0.0.0-00010101000000-000000000000
	github.com/maintainerd/secret v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.83.1
)

require (
	github.com/MicahParks/jwkset v0.11.1 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/maintainerd/secret => ../maintainerd-secret
