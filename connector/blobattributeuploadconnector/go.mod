module github.com/open-telemetry/opentelemetry-collector-contrib/connector/blobattributeuploadconnector

go 1.23

require (
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl v0.108.0
	github.com/stretchr/testify v1.9.0
	go.opentelemetry.io/collector/component v0.108.1
	go.opentelemetry.io/collector/confmap v1.14.1
	go.opentelemetry.io/collector/connector v0.108.1
	go.opentelemetry.io/collector/consumer v0.108.1
	go.opentelemetry.io/collector/consumer/consumertest v0.108.1
	go.opentelemetry.io/collector/pdata v1.14.1
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
	gocloud.dev v0.39.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cloud.google.com/go v0.115.1 // indirect
	cloud.google.com/go/auth v0.9.3 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.4 // indirect
	cloud.google.com/go/compute/metadata v0.5.0 // indirect
	cloud.google.com/go/iam v1.2.0 // indirect
	cloud.google.com/go/storage v1.43.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.14.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.4.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/alecthomas/participle/v2 v2.1.1 // indirect
	github.com/aws/aws-sdk-go v1.55.5 // indirect
	github.com/aws/aws-sdk-go-v2 v1.30.5 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.4 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.33 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.32 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.13 // indirect
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.61.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.7 // indirect
	github.com/aws/smithy-go v1.20.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elastic/go-grok v0.3.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.1.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/s2a-go v0.1.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/google/wire v0.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.3 // indirect
	github.com/googleapis/gax-go/v2 v2.13.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal v0.108.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.20.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/collector v0.108.1 // indirect
	go.opentelemetry.io/collector/component/componentprofiles v0.108.1 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.108.1 // indirect
	go.opentelemetry.io/collector/consumer/consumerprofiles v0.108.1 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.108.1 // indirect
	go.opentelemetry.io/collector/semconv v0.108.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.54.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.54.0 // indirect
	go.opentelemetry.io/otel v1.29.0 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.50.0 // indirect
	go.opentelemetry.io/otel/metric v1.29.0 // indirect
	go.opentelemetry.io/otel/sdk v1.28.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.29.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	golang.org/x/time v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/api v0.196.0 // indirect
	google.golang.org/genproto v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/grpc v1.66.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

// Use local copies for dependencies from this repository
replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl => ../../pkg/ottl
