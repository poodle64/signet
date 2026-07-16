// material.go: the broker's GET /v1/credentials/{name} envelope shape,
// narrowed to what the credential-vend consumers (headers, vend-to-file)
// need. Shared here because both attest fresh, vend, then resolve a value
// (or, for vend-to-file, one of several) out of the same envelope shape.
package attest

// credentialField is one {name, value} pair inside static credential material.
type credentialField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// credentialMaterial is the `material` object of a broker Credential
// envelope. `Fields` is populated for `kind == "static"`; `AccessToken` is
// populated for `kind == "session"` when the vendor exposes a bearer — a
// cookie-only session carries no access_token, which is a normal, expected
// shape. The broker's `cookies` and any other session extras are
// deliberately left unparsed here: no consumer in this package resolves a
// value out of them, so they can never reach an error path.
type credentialMaterial struct {
	Kind        string            `json:"kind"`
	Fields      []credentialField `json:"fields,omitempty"`
	AccessToken string            `json:"access_token,omitempty"`
}

// credentialEnvelope is the broker's GET /v1/credentials/{name} response
// shape, narrowed to what this package reads.
type credentialEnvelope struct {
	Material credentialMaterial `json:"material"`
}
