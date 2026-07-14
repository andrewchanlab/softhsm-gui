package local

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/andrewchanlab/softhsm-gui/internal/hsm"
	"github.com/miekg/pkcs11"
)

// Backend implements hsm.Backend for local SoftHSM via PKCS#11
type Backend struct {
	libPath   string
	slotID    uint
	userPIN   string
	session   pkcs11.SessionHandle
	p11       *pkcs11.Ctx
	connected bool
}

// NewBackend creates a new local SoftHSM backend
// libPath: path to libsofthsm2.so (e.g., "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
func NewBackend(libPath string) *Backend {
	return &Backend{libPath: libPath}
}

// Connect implements hsm.Backend
func (b *Backend) Connect(ctx context.Context) error {
	p11 := pkcs11.New(b.libPath)
	if err := p11.Initialize(); err != nil {
		return fmt.Errorf("pkcs11 initialize: %w", err)
	}
	b.p11 = p11
	b.connected = true
	return nil
}

// Disconnect implements hsm.Backend
func (b *Backend) Disconnect() error {
	if b.p11 != nil {
		b.p11.Finalize()
		b.p11 = nil
	}
	b.connected = false
	return nil
}

// IsConnected implements hsm.Backend
func (b *Backend) IsConnected() bool {
	return b.connected
}

// Name implements hsm.Backend
func (b *Backend) Name() string {
	return "Local SoftHSM (" + b.libPath + ")"
}

// Config implements hsm.Backend
func (b *Backend) Config() map[string]string {
	return map[string]string{
		"libPath": b.libPath,
		"slotID":  fmt.Sprintf("%d", b.slotID),
	}
}

// ListSlots implements hsm.Backend
func (b *Backend) ListSlots(ctx context.Context) ([]hsm.SlotInfo, error) {
	slots, err := b.p11.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("get slot list: %w", err)
	}

	var result []hsm.SlotInfo
	for _, slot := range slots {
		info, err := b.p11.GetSlotInfo(slot)
		if err != nil {
			continue
		}
		tokenInfo, _ := b.p11.GetTokenInfo(slot)
		si := hsm.SlotInfo{
			SlotID:      slot,
			TokenLabel:  strings.TrimRight(string(info.SlotDescription), " "),
			TokenSerial: strings.TrimRight(string(tokenInfo.SerialNumber), " "),
			Initialized: tokenInfo.SerialNumber != "",
			PINInit:     tokenInfo.SerialNumber != "",
			ReadOnly:    false,
		}
		result = append(result, si)
	}
	return result, nil
}

// InitToken implements hsm.Backend
func (b *Backend) InitToken(ctx context.Context, slotID uint, label, soPIN, userPIN string) error {
	return b.p11.InitToken(slotID, soPIN, label)
}

// DeleteToken implements hsm.Backend
func (b *Backend) DeleteToken(ctx context.Context, slotID uint) error {
	return fmt.Errorf("not implemented: use softhsm2-util CLI")
}

// OpenSession implements hsm.Backend
func (b *Backend) OpenSession(ctx context.Context, slotID uint, userPIN string) error {
	session, err := b.p11.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	if err := b.p11.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
		b.p11.CloseSession(session)
		return fmt.Errorf("login: %w", err)
	}
	b.session = session
	b.slotID = slotID
	b.userPIN = userPIN
	return nil
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
	err := b.p11.FindObjectsInit(b.session, nil)
	if err != nil {
		return nil, err
	}
	defer b.p11.FindObjectsFinal(b.session)

	var objects []hsm.HSMObject
	for {
		objs, _, err := b.p11.FindObjects(b.session, 100)
		if err != nil || len(objs) == 0 {
			break
		}
		for _, obj := range objs {
			attrs, err := b.p11.GetAttributeValue(b.session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			})
			if err != nil {
				continue
			}
			m := make(map[uint][]byte)
			for _, a := range attrs {
				m[a.Type] = a.Value
			}

			class := hsm.ObjectClass(m[pkcs11.CKA_CLASS][0])
			hsmo := hsm.HSMObject{
				Label: string(m[pkcs11.CKA_LABEL]),
				ID:    m[pkcs11.CKA_ID],
				Class: class,
			}
			if class == hsm.ClassPublicKey || class == hsm.ClassPrivateKey {
				if kt, ok := m[pkcs11.CKA_KEY_TYPE]; ok {
					if len(kt) >= 2 {
						ktVal := uint(kt[0])<<8 | uint(kt[1])
						if ktVal == pkcs11.CKK_RSA {
							hsmo.KeyType = hsm.KeyTypeRSA
						} else if ktVal == pkcs11.CKK_EC || ktVal == pkcs11.CKK_ECDSA {
							hsmo.KeyType = hsm.KeyTypeEC
						}
					}
				}
			}
			objects = append(objects, hsmo)
		}
	}
	return objects, nil
}

// GenerateKey implements hsm.Backend
func (b *Backend) GenerateKey(ctx context.Context, params hsm.KeyGenParams) error {
	switch params.KeyType {
	case hsm.KeyTypeRSA:
		return b.generateRSA(ctx, params)
	case hsm.KeyTypeEC:
		return b.generateEC(ctx, params)
	default:
		return fmt.Errorf("unsupported key type: %s", params.KeyType)
	}
}

func (b *Backend) generateRSA(ctx context.Context, params hsm.KeyGenParams) error {
	pubAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, params.Bits),
	}
	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, params.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, params.ID),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
	}

	pub, priv, err := b.p11.GenerateKeyPair(b.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubAttrs, privAttrs)
	if err != nil {
		return err
	}
	_ = priv
	_ = pub
	return nil
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

	pub, priv, err := b.p11.GenerateKeyPair(b.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubAttrs, privAttrs)
	if err != nil {
		return err
	}
	_ = priv
	_ = pub
	return nil
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
	m := make(map[uint][]byte)
	for _, a := range attrs {
		m[a.Type] = a.Value
	}

	var derBytes []byte

	if _, ok := m[pkcs11.CKA_EC_POINT]; ok {
		// EC public key
		derBytes = m[pkcs11.CKA_EC_POINT]
	} else if modulus, ok := m[pkcs11.CKA_MODULUS]; ok {
		// RSA public key
		exp := []byte{1, 0, 1} // default 65537
		if e, ok := m[pkcs11.CKA_PUBLIC_EXPONENT]; ok {
			exp = e
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(new(big.Int).SetBytes(exp).Int64()),
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

// DeleteObject implements hsm.Backend
func (b *Backend) DeleteObject(ctx context.Context, label string) error {
	err := b.p11.FindObjectsInit(b.session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return err
	}
	defer b.p11.FindObjectsFinal(b.session)

	objs, _, err := b.p11.FindObjects(b.session, 10)
	if err != nil {
		return err
	}
	for _, obj := range objs {
		b.p11.DestroyObject(b.session, obj)
	}
	return nil
}

// curveToOID maps curve name to OID bytes
func curveToOID(curve string) ([]byte, error) {
	switch curve {
	case "P-256", "secp256r1":
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil
	case "P-384", "secp384r1":
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, nil
	case "P-521", "secp521r1":
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}, nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s (use P-256, P-384, or P-521)", curve)
	}
}
