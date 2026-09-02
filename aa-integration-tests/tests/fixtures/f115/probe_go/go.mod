module probe_go

go 1.26.0

require github.com/ai-agent-assembly/go-sdk v0.0.0

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ai-agent-assembly/go-sdk => /tmp/aa-go-sdk-for-test
