package credential

import "context"

// DeviceLogin is a vault platform authorized by a device login the browser
// starts and then polls (begin → complete), instead of the Feishu OAuth
// redirect lark-cli uses. The open-source edition links none; an edition adds
// its own through platform.Drivers.
type DeviceLogin interface {
	// Descriptor names the platform and carries its /credentials page copy.
	Descriptor() DeviceLoginDescriptor
	// Available reports whether this pod can run the provider.
	Available() bool
	// Begin starts a login. Payload is sealed into the pending record so
	// Complete may run on another pod.
	Begin(ctx context.Context) DeviceLoginBegin
	// Complete polls a pending login; pending is the opened Begin payload
	// (always a JSON object).
	Complete(ctx context.Context, pending []byte) DeviceLoginComplete
	// Mint turns a stored credential into short-lived variables. keys opens
	// rec.Sealed and seals any write-back.
	Mint(ctx context.Context, keys *Keys, rec Record) MintResult
}

// DeviceLoginDescriptor identifies a device-login platform.
type DeviceLoginDescriptor struct {
	// Platform is the vault platform name (routes, storage, machine grants).
	Platform string
	// Kind is the stored CredentialDoc kind.
	Kind string
	// Title and Description are the page card copy.
	Title       string
	Description string
	// Linked lists services that share this authorization.
	Linked []LinkedService
}

// LinkedService is a service covered by another platform's authorization.
type LinkedService struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// DeviceLoginBegin carries the login link and the payload to seal as the
// pending record; Detail explains a failure.
type DeviceLoginBegin struct {
	OK      bool
	AuthURL string
	Payload any
	Detail  string
}

// DeviceLoginState is the outcome of polling a pending login.
type DeviceLoginState string

const (
	DeviceLoginAuthorized  DeviceLoginState = "authorized"
	DeviceLoginPending     DeviceLoginState = "pending"
	DeviceLoginFailed      DeviceLoginState = "failed"
	DeviceLoginUnavailable DeviceLoginState = "unavailable"
)

// DeviceLoginComplete: Payload, Account and LoginExpiresAt only when
// authorized; Detail for failed and unavailable. A failed login is dropped,
// any other state keeps the pending record for another poll.
type DeviceLoginComplete struct {
	State DeviceLoginState
	// Payload is sealed as the stored credential.
	Payload any
	Account string
	// LoginExpiresAt is ms; 0 when unknown.
	LoginExpiresAt int64
	Detail         string
}
