module github.com/sagearbor/personhood/tools/gen-ts-fixture

go 1.22.0

require (
	github.com/sagearbor/personhood/pkg/types v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/credential v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/policy v0.0.0-00010101000000-000000000000
)

require (
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/sagearbor/personhood/pkg/types => ../../pkg/types

replace github.com/sagearbor/personhood/src/credential => ../../src/credential

replace github.com/sagearbor/personhood/src/policy => ../../src/policy
