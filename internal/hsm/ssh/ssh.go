package ssh

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/andrewchanlab/softhsm-gui/internal/hsm"
)

// Backend implements hsm.Backend for remote SoftHSM via SSH
type Backend struct {
	host    string // user@host:port
	binary  string // path to softhsm2-util on remote
	conn    *sshConnection
	slotID  uint
	session *sshSession
}

type sshConnection struct {
	host string
}

type sshSession struct {
	slotID  uint
	userPIN string
}

var curveOIDMap = map[string]string{
	"secp256r1": "06082a8648ce3d030107",
	"secp384r1": "06052b81040022",
	"secp521r1": "06052b81040023",
}

// NewBackend creates a new SSH backend
// host: user@hostname or user@hostname:port
func NewBackend(host string) *Backend {
	return &Backend{
		host:   host,
		binary: "softhsm2-util",
	}
}

// Name implements hsm.Backend
func (b *Backend) Name() string { return "SSH: " + b.host }

// Config implements hsm.Backend
func (b *Backend) Config() map[string]string {
	return map[string]string{
		"host":   b.host,
		"binary": b.binary,
	}
}

func (b *Backend) ssh(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh", append([]string{b.host, b.binary}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh %s: %s", strings.Join(args, " "), stderr.String())
	}
	return string(out), nil
}

// Connect implements hsm.Backend
func (b *Backend) Connect(ctx context.Context) error {
	// Test connectivity
	out, err := b.ssh(ctx, "--show-slots")
	if err != nil {
		return fmt.Errorf("SSH connection test failed: %w", err)
	}
	if strings.Contains(out, "error") || strings.Contains(out, "Error") {
		return fmt.Errorf("softhsm2-util error: %s", out)
	}
	return nil
}

// Disconnect implements hsm.Backend
func (b *Backend) Disconnect() error {
	b.session = nil
	return nil
}

// IsConnected implements hsm.Backend
func (b *Backend) IsConnected() bool { return b.session != nil }

// ListSlots implements hsm.Backend
func (b *Backend) ListSlots(ctx context.Context) ([]hsm.SlotInfo, error) {
	out, err := b.ssh(ctx, "--show-slots")
	if err != nil {
		return nil, err
	}
	return parseSlots(out), nil
}

func parseSlots(text string) []hsm.SlotInfo {
	var slots []hsm.SlotInfo
	lines := strings.Split(text, "\n")
	var current *hsm.SlotInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Slot ") {
			if current != nil {
				slots = append(slots, *current)
			}
			idStr := strings.TrimPrefix(line, "Slot ")
			idStr = strings.TrimRight(idStr, ":")
			id, _ := strconv.ParseUint(idStr, 10, 32)
			current = &hsm.SlotInfo{SlotID: uint(id)}
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "Token present:") {
			current.Initialized = strings.Contains(line, "yes")
		}
		if strings.HasPrefix(line, "Label:") {
			current.TokenLabel = strings.TrimPrefix(line, "Label:")
		}
		if strings.HasPrefix(line, "Initialized:") {
			current.Initialized = strings.Contains(line, "yes")
		}
		if strings.HasPrefix(line, "User PIN init.:") {
			current.PINInit = strings.Contains(line, "yes")
		}
		if strings.HasPrefix(line, "Serial number:") {
			current.TokenSerial = strings.TrimPrefix(line, "Serial number:")
		}
	}
	if current != nil {
		slots = append(slots, *current)
	}
	return slots
}

// InitToken implements hsm.Backend
func (b *Backend) InitToken(ctx context.Context, slotID uint, label, soPIN, userPIN string) error {
	_, err := b.ssh(ctx,
		"--init-token",
		"--slot", fmt.Sprintf("%d", slotID),
		"--label", label,
		"--so-pin", soPIN,
		"--pin", userPIN,
	)
	return err
}

// DeleteToken implements hsm.Backend
func (b *Backend) DeleteToken(ctx context.Context, slotID uint) error {
	_, err := b.ssh(ctx, "--delete-token", "--slot", fmt.Sprintf("%d", slotID))
	return err
}

// OpenSession implements hsm.Backend
func (b *Backend) OpenSession(ctx context.Context, slotID uint, userPIN string) error {
	b.session = &sshSession{slotID: slotID, userPIN: userPIN}
	b.slotID = slotID
	return nil
}

// CloseSession implements hsm.Backend
func (b *Backend) CloseSession() error {
	b.session = nil
	return nil
}

// ListObjects uses a remote Python script via SSH
func (b *Backend) ListObjects(ctx context.Context) ([]hsm.HSMObject, error) {
	if b.session == nil {
		return nil, fmt.Errorf("no session open")
	}
	script := buildListObjectsScript(b.binary, b.session.slotID, b.session.userPIN)
	out, err := b.ssh(ctx, "python3", "-c", script)
	if err != nil {
		return nil, err
	}
	var objects []hsm.HSMObject
	if err := json.Unmarshal([]byte(out), &objects); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return objects, nil
}

func buildListObjectsScript(libPath string, slotID uint, userPIN string) string {
	return fmt.Sprintf(`
import sys,json
sys.path.insert(0,'/usr/local/lib/python3.14/dist-packages')
from pkcs11.lib import PKCS11
lib=PKCS11('%s')
slots=lib.get_slots()
if %d>=len(slots):print('[]');sys.exit()
token=slots[%d].get_token()
session=token.open(user_pin='%s')
objects=[]
for obj in session.get_objects():
    try:
        label=obj.label or ''
        kid=obj.id.hex() if obj.id else ''
        cls=obj.object_class
        type_map={1:'DATA',2:'CERT',3:'PUBKEY',4:'PRIVKEY',5:'SECRET'}
        objects.append({'label':label,'id':kid,'class':cls,'key_type':type_map.get(cls,'UNK')})
    except:pass
print(json.dumps(objects))
`, libPath, slotID, slotID, userPIN)
}

// GenerateKey via softhsm2-util key generation on remote
func (b *Backend) GenerateKey(ctx context.Context, params hsm.KeyGenParams) error {
	// Use softhsm2-util to generate a key and import it
	// For now, use the remote Python script approach
	if b.session == nil {
		return fmt.Errorf("no session open")
	}
	script := buildGenKeyScript(b.binary, b.session.slotID, b.session.userPIN, params)
	out, err := b.ssh(ctx, "python3", "-c", script)
	if err != nil {
		return fmt.Errorf("GenerateKey: %s", out)
	}
	if !strings.Contains(out, "OK") {
		return fmt.Errorf("GenerateKey failed: %s", out)
	}
	return nil
}

func buildGenKeyScript(libPath string, slotID uint, userPIN string, params hsm.KeyGenParams) string {
	idHex := hex.EncodeToString(params.ID)
	if params.KeyType == hsm.KeyTypeRSA {
		return fmt.Sprintf(`
import sys
sys.path.insert(0,'/usr/local/lib/python3.14/dist-packages')
from pkcs11.lib import PKCS11
from pkcs11 import KeyType
lib=PKCS11('%s')
slot=lib.get_slots()[%d]
token=slot.get_token()
session=token.open(user_pin='%s')
pub,priv=session.generate_keypair(KeyType.RSA,%d,label='%s',id=bytes.fromhex('%s'))
print('OK')
`, libPath, slotID, userPIN, params.Bits, params.Label, idHex)
	}
	// EC key
	curve := curveOIDMap[params.Curve]
	if curve == "" {
		curve = curveOIDMap["secp256r1"]
	}
	return fmt.Sprintf(`
import sys,os
os.environ['SOFTHSM2_CONF']='/dev/null'
sys.path.insert(0,'/usr/local/lib/python3.14/dist-packages')
from pkcs11.lib import PKCS11
from pkcs11 import KeyType,mechanisms,attributes
lib=PKCS11('%s')
slot=lib.get_slots()[%d]
token=slot.get_token()
session=token.open(user_pin='%s')
ec_der=bytes.fromhex('%s')
pub,priv=session.generate_keypair(
    KeyType.EC,key_length=%d,
    mechanism=mechanisms.Mechanism.EC_KEY_PAIR_GEN,
    mechanism_param=ec_der,
    label='%s',id=bytes.fromhex('%s'),
    public_template={attributes.Attribute.EC_PARAMS:ec_der})
print('OK')
`, libPath, slotID, userPIN, curve, curveToBits(params.Curve), params.Label, idHex)
}

func curveToBits(curve string) int {
	switch curve {
	case "secp256r1": return 256
	case "secp384r1": return 384
	case "secp521r1": return 521
	default: return 256
	}
}

// ImportKey via softhsm2-util --import on remote
func (b *Backend) ImportKey(ctx context.Context, label, pkcs8Path, filePIN string) error {
	if b.session == nil {
		return fmt.Errorf("no session open")
	}
	args := []string{
		"--import", pkcs8Path,
		"--slot", fmt.Sprintf("%d", b.session.slotID),
		"--label", label,
		"--id", hex.EncodeToString([]byte(b.session.userPIN)[:1]),
		"--pin", b.session.userPIN,
	}
	if filePIN != "" {
		args = append(args, "--file-pin", filePIN)
	}
	_, err := b.ssh(ctx, args...)
	return err
}

// ExportPublicKey via remote Python script
func (b *Backend) ExportPublicKey(ctx context.Context, label string) ([]byte, error) {
	if b.session == nil {
		return nil, fmt.Errorf("no session open")
	}
	script := buildExportScript(b.binary, b.session.slotID, b.session.userPIN, label)
	out, err := b.ssh(ctx, "python3", "-c", script)
	if err != nil {
		return nil, fmt.Errorf("ExportPublicKey: %s", out)
	}
	return []byte(out), nil
}

func buildExportScript(libPath string, slotID uint, userPIN, label string) string {
	return fmt.Sprintf(`
import sys,base64
sys.path.insert(0,'/usr/local/lib/python3.14/dist-packages')
from pkcs11.lib import PKCS11
lib=PKCS11('%s')
slot=lib.get_slots()[%d]
token=slot.get_token()
session=token.open(user_pin='%s')
for obj in session.get_objects():
    try:
        if obj.label=='%s' and obj.object_class==3:
            der=obj.export()
            b64=base64.b64encode(der).decode()
            for i in range(0,len(b64),64):print(b64[i:i+64])
            break
    except:pass
`, libPath, slotID, userPIN, label)
}

// DeleteObject via remote Python script
func (b *Backend) DeleteObject(ctx context.Context, label string) error {
	if b.session == nil {
		return fmt.Errorf("no session open")
	}
	script := fmt.Sprintf(`
import sys
sys.path.insert(0,'/usr/local/lib/python3.14/dist-packages')
from pkcs11.lib import PKCS11
lib=PKCS11('%s')
slot=lib.get_slots()[%d]
token=slot.get_token()
session=token.open(user_pin='%s')
for obj in session.get_objects():
    try:
        if obj.label=='%s':obj.destroy()
    except:pass
print('OK')
`, b.binary, b.session.slotID, b.session.userPIN, label)
	out, err := b.ssh(ctx, "python3", "-c", script)
	if err != nil {
		return fmt.Errorf("DeleteObject: %s", out)
	}
	return nil
}
