package hsm

import (
	"context"
	"time"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeRSA KeyType = "RSA"
	KeyTypeEC  KeyType = "EC"
)

// ObjectClass represents PKCS#11 object classes
type ObjectClass uint

const (
	ClassPublicKey  ObjectClass = 1
	ClassPrivateKey ObjectClass = 2
	ClassSecretKey  ObjectClass = 3
	ClassCertificate ObjectClass = 4
)

// HSMObject represents an object stored in the HSM
type HSMObject struct {
	Label      string
	ID         []byte
	Class      ObjectClass
	KeyType    KeyType
	Attributes map[string]string
}

// SlotInfo represents a PKCS#11 slot
type SlotInfo struct {
	SlotID      uint
	TokenLabel  string
	TokenSerial string
	Initialized bool
	PINInit     bool
	ReadOnly    bool
}

// KeyGenParams holds parameters for key generation
type KeyGenParams struct {
	Label    string
	ID       []byte    // hex string for input, bytes for storage
	KeyType  KeyType   // RSA or EC
	Bits     int       // for RSA: 2048, 4096, etc.
	Curve    string    // for EC: secp256r1, secp384r1, secp521r1
}

// Backend defines the interface for HSM operations
// Each backend (local PKCS#11, SSH, etc.) implements this interface
type Backend interface {
	// Connect establishes connection to the HSM
	Connect(ctx context.Context) error

	// Disconnect closes the connection
	Disconnect() error

	// IsConnected returns true if currently connected
	IsConnected() bool

	// ListSlots returns all available slots
	ListSlots(ctx context.Context) ([]SlotInfo, error)

	// InitToken initializes a new token in the given slot
	InitToken(ctx context.Context, slotID uint, label, soPIN, userPIN string) error

	// DeleteToken removes a token from the slot
	DeleteToken(ctx context.Context, slotID uint) error

	// OpenSession opens a session with the token (user PIN)
	OpenSession(ctx context.Context, slotID uint, userPIN string) error

	// CloseSession closes the current session
	CloseSession() error

	// ListObjects returns all objects in the current session
	ListObjects(ctx context.Context) ([]HSMObject, error)

	// GenerateKey generates a new RSA or EC key pair
	GenerateKey(ctx context.Context, params KeyGenParams) error

	// ImportKey imports a PKCS#8 private key
	ImportKey(ctx context.Context, label, pkcs8Path, filePIN string) error

	// ExportPublicKey exports a public key as PEM
	ExportPublicKey(ctx context.Context, label string) ([]byte, error)

	// DeleteObject removes an object from the HSM
	DeleteObject(ctx context.Context, label string) error

	// Name returns the backend name (e.g., "Local SoftHSM", "SSH: user@host")
	Name() string

	// Config returns backend-specific config as key-value pairs
	Config() map[string]string
}

// Timeout context helpers
func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
