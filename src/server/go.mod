module github.com/sagearbor/personhood/src/server

go 1.22.0

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/sagearbor/personhood/pkg/types v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/credential v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/methods/email v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/methods/government-id-liveness v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/methods/sms v0.0.0-00010101000000-000000000000
	github.com/sagearbor/personhood/src/registry v0.0.0-00010101000000-000000000000
)

require github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect

replace (
	github.com/sagearbor/personhood/pkg/types => ../../pkg/types
	github.com/sagearbor/personhood/src/credential => ../credential
	github.com/sagearbor/personhood/src/methods/email => ../methods/email
	github.com/sagearbor/personhood/src/methods/government-id-liveness => ../methods/government-id-liveness
	github.com/sagearbor/personhood/src/methods/sms => ../methods/sms
	github.com/sagearbor/personhood/src/policy => ../policy
	github.com/sagearbor/personhood/src/registry => ../registry
)
