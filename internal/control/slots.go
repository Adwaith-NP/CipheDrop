package control

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cipherdrop/internal/filelock"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/trust"
)

// MaxAttempts is how many failed enrolment attempts a slot tolerates before
// it locks. With 6-digit codes an attacker holding the link has at most
// 5 in 1,000,000 chances.
const MaxAttempts = 5

// Slot states.
const (
	SlotOpen      = "open"
	SlotUsed      = "used"
	SlotLocked    = "locked"
	SlotExpired   = "expired"
	SlotCancelled = "cancelled"
)

// Slot kinds.
const (
	KindEnroll = "enroll" // a new machine joins
	KindRenew  = "renew"  // an enrolled machine gets a fresh key and certificate
)

// Certificate validity the admin can choose per slot, in days.
const (
	DefaultDays = 365
	MaxDays     = 1825 // never beyond the 5-year issuing CA
)

// Slot is a machine the admin has pre-registered and may enrol once.
type Slot struct {
	ID              string    `json:"id"`
	Kind            string    `json:"kind,omitempty"`     // "" means enroll (older records)
	Days            int       `json:"days,omitempty"`     // validity of the certificate to issue
	RenewOf         string    `json:"renew_of,omitempty"` // fingerprint of the certificate being renewed
	TokenHash       []byte    `json:"token_hash"`         // SHA-256 of the link token; the token itself is never stored
	Name            string    `json:"name"`
	Department      string    `json:"department"`
	Purpose         string    `json:"purpose"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Status          string    `json:"status"`
	Attempts        int       `json:"attempts"`
	UsedAt          time.Time `json:"used_at,omitzero"`
	UsedFrom        string    `json:"used_from,omitempty"`
	CertSerial      string    `json:"cert_serial,omitempty"`
	CertFingerprint string    `json:"cert_fingerprint,omitempty"`
	CertNotAfter    time.Time `json:"cert_not_after,omitzero"`
}

// EffectiveStatus reports "expired" for an open slot past its deadline.
func (s Slot) EffectiveStatus(now time.Time) string {
	if s.Status == SlotOpen && now.After(s.ExpiresAt) {
		return SlotExpired
	}
	return s.Status
}

func (p Paths) slotFile(id string) string { return filepath.Join(p.Slots(), id+".json") }

// IsRenewal reports whether the slot renews an existing device.
func (s Slot) IsRenewal() bool { return s.Kind == KindRenew }

func validDays(days int) (int, error) {
	if days == 0 {
		return DefaultDays, nil
	}
	if days < 1 || days > MaxDays {
		return 0, fmt.Errorf("validity must be 1-%d days", MaxDays)
	}
	return days, nil
}

// CreateSlot pre-registers a machine and returns its one-time enrolment
// link. days is the validity of the certificate it will get (0 = 1 year).
func (s *Session) CreateSlot(name, department, purpose string, days int, ttl time.Duration, now time.Time) (Slot, provision.Link, error) {
	var none provision.Link
	days, err := validDays(days)
	if err != nil {
		return Slot{}, none, err
	}
	if err := identity.ValidateName(name); err != nil {
		return Slot{}, none, err
	}
	if err := ValidateDepartment(department); err != nil {
		return Slot{}, none, err
	}
	purpose = strings.TrimSpace(purpose)
	if len(purpose) > 200 {
		return Slot{}, none, errors.New("purpose is limited to 200 characters")
	}
	if ttl <= 0 || ttl > 7*24*time.Hour {
		return Slot{}, none, errors.New("link lifetime must be between 1 second and 7 days")
	}
	existing, err := ListSlots(s.Paths)
	if err != nil {
		return Slot{}, none, err
	}
	for _, e := range existing {
		if e.Name == name && (e.Status == SlotUsed || e.EffectiveStatus(now) == SlotOpen) {
			return Slot{}, none, fmt.Errorf("a device named %q is already enrolled or has an open slot", name)
		}
	}
	link, err := s.linkBase()
	if err != nil {
		return Slot{}, none, err
	}
	token := provision.NewToken()
	th := sha256.Sum256(token)
	slot := Slot{ID: provision.NewSlotID(), Kind: KindEnroll, Days: days, TokenHash: th[:], Name: name, Department: department,
		Purpose: purpose, CreatedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), Status: SlotOpen}
	if err := writeSlot(s.Paths, slot); err != nil {
		return Slot{}, none, err
	}
	link.SlotID, link.Token = slot.ID, token
	s.Audit.Append("admin", "slot_created", map[string]string{
		"slot": slot.ID, "name": name, "department": department, "purpose": purpose,
		"days": fmt.Sprint(days), "expires": slot.ExpiresAt.Format(time.RFC3339)})
	return slot, link, nil
}

// CurrentCert returns the most recent slot through which name received a
// certificate (enrolment or renewal), if any.
func CurrentCert(slots []Slot, name string) (Slot, bool) {
	var best Slot
	found := false
	for _, sl := range slots {
		if sl.Name == name && sl.Status == SlotUsed && (!found || sl.UsedAt.After(best.UsedAt)) {
			best, found = sl, true
		}
	}
	return best, found
}

// CreateRenewSlot creates a renewal link for an enrolled device. It keeps
// the device's name, department and purpose; the device proves it is the
// same machine by signing with its current key, and gets a new key and a
// certificate valid for days (0 = 1 year). Works before and after expiry.
func (s *Session) CreateRenewSlot(name string, days int, ttl time.Duration, now time.Time) (Slot, provision.Link, error) {
	var none provision.Link
	days, err := validDays(days)
	if err != nil {
		return Slot{}, none, err
	}
	slots, err := ListSlots(s.Paths)
	if err != nil {
		return Slot{}, none, err
	}
	cur, ok := CurrentCert(slots, name)
	if !ok {
		return Slot{}, none, fmt.Errorf("no enrolled device named %q to renew", name)
	}
	for _, e := range slots {
		if e.Name == name && e.EffectiveStatus(now) == SlotOpen {
			return Slot{}, none, fmt.Errorf("%q already has an open slot; use it or cancel it first", name)
		}
	}
	link, err := s.linkBase()
	if err != nil {
		return Slot{}, none, err
	}
	token := provision.NewToken()
	th := sha256.Sum256(token)
	slot := Slot{ID: provision.NewSlotID(), Kind: KindRenew, Days: days, RenewOf: cur.CertFingerprint, TokenHash: th[:],
		Name: name, Department: cur.Department, Purpose: cur.Purpose, CreatedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), Status: SlotOpen}
	if err := writeSlot(s.Paths, slot); err != nil {
		return Slot{}, none, err
	}
	link.SlotID, link.Token, link.Renew = slot.ID, token, true
	s.Audit.Append("admin", "renewal_created", map[string]string{
		"slot": slot.ID, "name": name, "renews": cur.CertSerial, "days": fmt.Sprint(days),
		"expires": slot.ExpiresAt.Format(time.RFC3339)})
	return slot, link, nil
}

// linkBase fills in the parts of a link shared by every slot: the server
// address, its key pin and the root fingerprint.
func (s *Session) linkBase() (provision.Link, error) {
	var l provision.Link
	cert, err := trust.LoadCertFile(s.Paths.TLSCert())
	if err != nil {
		return l, fmt.Errorf("issuing CA not installed yet (%w); run install-issuing first", err)
	}
	root, err := trust.LoadCertFile(s.Paths.Root())
	if err != nil {
		return l, err
	}
	l.Host, l.Pin, l.CARoot = s.Config.PublicAddr, provision.SPKIHash(cert), sha256.Sum256(root.Raw)
	return l, nil
}

// ListSlots returns all slots, newest first.
func ListSlots(p Paths) ([]Slot, error) {
	entries, err := os.ReadDir(p.Slots())
	if err != nil {
		return nil, err
	}
	var out []Slot
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		sl, err := readSlot(p, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, sl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func readSlot(p Paths, id string) (Slot, error) {
	var sl Slot
	data, err := os.ReadFile(p.slotFile(id))
	if err != nil {
		return sl, err
	}
	return sl, json.Unmarshal(data, &sl)
}

func writeSlot(p Paths, sl Slot) error {
	data, _ := json.MarshalIndent(sl, "", "  ")
	tmp := p.slotFile(sl.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.slotFile(sl.ID))
}

// updateSlot loads a slot under an exclusive lock, lets fn change it, and
// always writes it back, so failed attempts are counted even when fn
// returns an error.
func updateSlot(p Paths, id string, fn func(*Slot) error) error {
	if _, err := os.Stat(p.slotFile(id)); err != nil {
		return err // do not create lock files for slots that do not exist
	}
	return filelock.With(p.slotFile(id)+".lock", func() error {
		sl, err := readSlot(p, id)
		if err != nil {
			return err
		}
		fnErr := fn(&sl)
		if err := writeSlot(p, sl); err != nil {
			return err
		}
		return fnErr
	})
}

// CancelSlot withdraws an open enrolment link (for example one that was
// lost), so its token can never be used and a new link can be issued.
func (s *Session) CancelSlot(nameOrID string, now time.Time) (Slot, error) {
	slots, err := ListSlots(s.Paths)
	if err != nil {
		return Slot{}, err
	}
	var id string
	for _, sl := range slots {
		if (sl.ID == nameOrID || sl.Name == nameOrID) && sl.EffectiveStatus(now) == SlotOpen {
			id = sl.ID
			break
		}
	}
	if id == "" {
		return Slot{}, fmt.Errorf("no open enrolment link for %q", nameOrID)
	}
	var out Slot
	err = updateSlot(s.Paths, id, func(sl *Slot) error {
		if sl.EffectiveStatus(now) != SlotOpen {
			return errors.New("that link is no longer open")
		}
		sl.Status = SlotCancelled
		out = *sl
		return nil
	})
	if err != nil {
		return Slot{}, err
	}
	s.Audit.Append("admin", "slot_cancelled", map[string]string{"slot": out.ID, "name": out.Name})
	return out, nil
}
