package local

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/andrewchanlab/softhsm-gui/internal/hsm"
	"github.com/miekg/pkcs11"
)

// Backend implements hsm.Backend for local SoftHSM via PKCS#11
type Backend struct {
	libPath  string
	slotID   uint
	userPIN  string
	session  pkcs11.SessionHandle
	p11      *pkcs11.Ctx
	connected bool
}

// NewBackend creates a new local SoftHSM backend
// libPath: path to libsofthsm2.so (e.g., "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
func NewBackend(libPath string) *Backend {
	return &Backend{libPath: libPath}
}

// Name implements hsm.Backend
func (b *Backend) Name() string { return "Local SoftHSM (PKCS#11)" }

// Config implements hsm.Backend
func (b *Backend) Config() map[string]string {
	return map[string]string{
		"library": b.libPath,
	}
}

// Connect implements hsm.Backend
func (b *Backend) Connect(ctx context.Context) error {
	var err error
	b.p11 = pkcs11.New(b.libPath)
	if b.p11 == nil {
		return fmt.Errorf("failed to load PKCS#11 library: %s", b.libPath)
	}
	if err = b.p11.Initialize(); err != nil {
		// Some implementations require re-init
		b.p11.Finalize()
		b.p11.Initialize()
	}
	b.connected = true
	return nil
}

// Disconnect implements hsm.Backend
func (b *Backend) Disconnect() error {
	if b.session != 0 {
		b.p11.CloseSession(b.session)
		b.session = 0
	}
	if b.p11 != nil {
		b.p11.Finalize()
		b.p11.Destroy()
		b.p11 = nil
	}
	b.connected = false
	return nil
}

// IsConnected implements hsm.Backend
func (b *Backend) IsConnected() bool { return b.connected }

// ListSlots implements hsm.Backend
func (b *Backend) ListSlots(ctx context.Context) ([]hsm.SlotInfo, error) {
	slots, err := b.p11.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("GetSlotList: %w", err)
	}

	var result []hsm.SlotInfo
	for _, slot := range slots {
		si, err := b.p11.GetSlotInfo(slot)
		if err != nil {
			continue
		}
		ti, _ := b.p11.GetTokenInfo(slot)
		result = append(result, hsm.SlotInfo{
			SlotID:      slot,
			TokenLabel:  strings.TrimSpace(string(ti.Label[:])),
			TokenSerial: strings.TrimSpace(string(ti.SerialNumber[:])),
			Initialized: ti.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0,
			PINInit:     ti.Flags&pkcs11.CKF_USER_PIN_INITIALIZED != 0,
			ReadOnly:    si.Flags&pkcs11.CKF_WRITE_PROTECTED != 0,
		})
	}
	return result, nil
}

// InitToken implements hsm.Backend
func (b *Backend) InitToken(ctx context.Context, slotID uint, label, soPIN, userPIN string) error {
	return b.p11.InitToken(slotID, soPIN, label)
}

// DeleteToken implements hsm.Backend
func (b *Backend) DeleteToken(ctx context.Context, slotID uint) error {
	return fmt.Errorf("not implemented: use softhsm2-util CLI for token deletion")
}

// OpenSession implements hsm.Backend
func (b *Backend) OpenSession(ctx context.Context, slotID uint, userPIN string) error {
	var err error
	b.session, err = b.p11.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("OpenSession: %w", err)
	}
	b.slotID = slotID
	b.userPIN = userPIN
	return b.p11.Login(b.session, pkcs11.CKU_USER, userPIN)
}

// CloseSession implements hsm.Backend
func (b *Backend) CloseSession() error {
	if b.session != 0 {
		b.p11.Logout(b.session)
		b.p11.CloseSession(b.session)
		b.session = 0
	}
	return nil
}

// ListObjects implements hsm.Backend
func (b *Backend) ListObjects(ctx context.Context) ([]hsm.HSMObject, error) {
	var objects []hsm.HSMObject

	err := b.p11.FindObjectsInit(b.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, err
	}
	defer b.p11.FindObjectsFinal(b.session)

	for {
		objs, _, err := b.p11.FindObjects(b.session, 100)
		if err != nil {
			return nil, err
		}
		if len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			attrs, _ := b.p11.GetAttributeValue(b.session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			})
			m := make(map[pkcs11.AttributeType][]byte)
			for _, a := range attrs {
				m[a.Type] = a.Value
			}

			var class hsm.ObjectClass
			if v, ok := m[pkcs11.CKA_CLASS]; ok && len(v) >= 4 {
				class = hsm.ObjectClass(uint(v[0])<<24 | uint(v[1])<<16 | uint(v[2])<<8 | uint(v[3]))
			}

			var kt hsm.KeyType
			if v, ok := m[pkcs11.CKA_KEY_TYPE]; ok && len(v) >= 2 {
				ktVal := uint(v[0])<<8 | uint(v[1])
				if ktVal == pkcs11.CKK_RSA {
					kt = hsm.KeyTypeRSA
				} else if ktVal == pkcs11.CKK_EC {
					kt = hsm.KeyTypeEC
				}
			}

			objects = append(objects, hsm.HSMObject{
				Label: string(m[pkcs11.CKA_LABEL]),
				ID:    m[pkcs11.CKA_ID],
				Class: class,
				KeyType: kt,
			})
		}
	}
	return objects, nil
}

// GenerateKey implements hsm.Backend
func (b *Backend) GenerateKey(ctx context.Context, params hsm.KeyGenParams) error {
	if params.KeyType == hsm.KeyTypeRSA {
		return b.generateRSA(ctx, params)
	}
	return b.generateEC(ctx, params)
}

func (b *Backend) generateRSA(ctx context.Context, params hsm.KeyGenParams) error {
	pubAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, params.Bits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
	}
	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	err := b.p11.GenerateKeyPair(b.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubAttrs, privAttrs)
	return err
}

func (b *Backend) generateEC(ctx context.Context, params hsm.KeyGenParams) error {
	curveOID, err := curveToOID(params.Curve)
	if err != nil {
		return err
	}

	pubAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curveOID),
	}
	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curveOID),
	}

	err = b.p11.GenerateKeyPair(b.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubAttrs, privAttrs)
	return err
}

// ImportKey implements hsm.Backend
func (b *Backend) ImportKey(ctx context.Context, label, pkcs8Path, filePIN string) error {
	return fmt.Errorf("not implemented: use softhsm2-util CLI for PKCS#8 import")
}

// ExportPublicKey implements hsm.Backend
func (b *Backend) ExportPublicKey(ctx context.Context, label string) ([]byte, error) {
	// Find the public key object
	err := b.p11.FindObjectsInit(b.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	})
	if err != nil {
		return nil, err
	}
	defer b.p11.FindObjectsFinal(b.session)

	objs, _, err := b.p11.FindObjects(b.session, 1)
	if err != nil || len(objs) == 0 {
		return nil, fmt.Errorf("public key not found: %s", label)
	}

	// Export as DER — get both EC_POINT (for EC) and MODULUS+EXPONENT (for RSA)
	attrs, err := b.p11.GetAttributeValue(b.session, objs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, err
	}
	m := make(map[pkcs11.AttributeType][]byte)
	for _, a := range attrs {
		m[a.Type] = a.Value
	}

	var derBytes []byte

	if ecPoint, ok := m[pkcs11.CKA_EC_POINT]; ok {
		// EC public key — parse uncompressed point
		derBytes = parseECPointDer(ecPoint)
	} else if modulus, ok := m[pkcs11.CKA_MODULUS]; ok {
		exp := []byte{1, 0, 1} // default 65537
		if e, ok := m[pkcs11.CKA_PUBLIC_EXPONENT]; ok {
			exp = e
		}
		rsaPub := &rsaPublicKey{
			N: new(bytes.Buffer),
			E: new(bytes.Buffer),
		}
		rsaPub.N.Write(modulus)
		rsaPub.E.Write(exp)
		pub := &x509.PublicKeyRSA{
			N: rsaPub.N.Bytes(),
			E: rsaPub.E.Bytes(),
		}
		derBytes, _ = x509.MarshalPKIXPublicKey(pub)
	}

	var pemBytes bytes.Buffer
	pem.Encode(&pemBytes, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})
	return pemBytes.Bytes(), nil
}

// parseECPointDer converts an X9.62 uncompressed EC point to SubjectPublicKeyInfo DER
func parseECPointDer(ecPoint []byte) []byte {
	// X9.62 format: 0x04 || x || y
	// Convert to SPKI: wrap in bitstring
	if len(ecPoint) < 65 {
		return ecPoint
	}
	x := ecPoint[1:33]
	y := ecPoint[33:65]
	// Build uncompressed ECPoint OCTET STRING
	octet := append([]byte{0x04}, x...)
	octet = append(octet, y...)
	// Tag 0x03 = BIT STRING, with 0 unused bits
	der := []byte{0x03, byte(1 + len(octet)), 0x00}
	der = append(der, octet...)
	return der
}

// DeleteObject implements hsm.Backend
func (b *Backend) DeleteObject(ctx context.Context, label string) error {
	err := b.p11.FindObjectsInit(b.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return err
	}
	defer b.p11.FindObjectsFinal(b.session)

	for {
		objs, _, err := b.p11.FindObjects(b.session, 10)
		if err != nil || len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			b.p11.DestroyObject(b.session, obj)
		}
	}
	return nil
}

// curveToOID returns the DER-encoded OID for a named curve
func curveToOID(curve string) ([]byte, error) {
	switch curve {
	case "secp256r1":
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil
	case "secp384r1":
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, nil
	case "secp521r1":
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}, nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}
}

type rsaPublicKey struct {
	N, E *bytes.Buffer
}

