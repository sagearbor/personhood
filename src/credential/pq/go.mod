module github.com/sagearbor/personhood/src/credential/pq

go 1.22.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/sagearbor/personhood/pkg/types v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/credential v0.0.0-00010101000000-000000000000
)

require (
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace (
	github.com/sagearbor/personhood/pkg/types => ../../../pkg/types
	github.com/sagearbor/personhood/src/credential => ../
)
