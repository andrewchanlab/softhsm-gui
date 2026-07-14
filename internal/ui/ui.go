package ui

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/andrewchanlab/softhsm-gui/internal/hsm"
	"github.com/andrewchanlab/softhsm-gui/internal/hsm/local"
	"github.com/andrewchanlab/softhsm-gui/internal/hsm/ssh"
)

// App is the main Fyne application
type App struct {
	fyneApp fyne.App
	window  fyne.Window

	// HSM backends
	backends []hsm.Backend
	activeBackend binding.String

	// State
	currentBackend hsm.Backend
	ctx    context.Context
	cancel context.CancelFunc

	// UI elements
	slotList     *widget.ListView
	objectsList  *widget.ListView
	slotInfo     *widget.MultiLineEntry
	statusBar    *widget.Label
	userPINEntry *widget.Entry

	slotData binding.UntypedList
	objData  binding.UntypedList
}

func NewApp() *App {
	a := &App{
		fyneApp:        app.NewWithID("com.c2hlab.softhsm-gui"),
		activeBackend:  binding.NewString(),
		slotData:       binding.NewUntypedList(),
		objData:        binding.NewUntypedList(),
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.initBackends()
	return a
}

func (a *App) Run() {
	a.window = a.fyneApp.NewWindow("SoftHSM v2 Manager")
	a.window.Resize(fyne.NewSize(900, 650))
	a.window.SetContent(a.buildUI())
	a.window.ShowAndRun()
}

func (a *App) initBackends() {
	// Default local SoftHSM path for Linux
	a.backends = []hsm.Backend{
		local.NewBackend("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
	}

	// Try to detect more paths
	paths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/libsofthsm2.so",
		"/lib/x86_64-linux-gnu/libsofthsm2.so",
	}
	for _, p := range paths {
		existing := false
		for _, b := range a.backends {
			if b.Config()["library"] == p {
				existing = true
				break
			}
		}
		if !existing {
			a.backends = append(a.backends, local.NewBackend(p))
		}
	}
}

func (a *App) buildUI() fyne.CanvasObject {
	// Header: source selector
	backendNames := make([]string, len(a.backends))
	backendByName := make(map[string]hsm.Backend)
	for i, b := range a.backends {
		name := b.Name()
		backendNames[i] = name
		backendByName[name] = b
	}

	sourceSelect := widget.NewSelect(backendNames, func(selected string) {
		a.activeBackend.Set(selected)
		if be, ok := backendByName[selected]; ok {
			a.currentBackend = be
			a.refreshSlots()
		}
	})
	if len(backendNames) > 0 {
		sourceSelect.Selected = backendNames[0]
		a.currentBackend = a.backends[0]
	}

	// Add SSH backend button
	addSSH := widget.NewButton("+ SSH Remote", func() {
		a.showAddSSHdialog()
	})

	header := container.NewBorder(
		nil, nil,
		widget.NewLabel("HSM Source:"),
		container.NewHBox(addSSH, widget.NewButton("⟳ Refresh", func() { a.refreshSlots() })),
		sourceSelect,
	)

	// Left panel: slots
	slotLabel := widget.NewLabel("Slots")
	slotLabel.TextStyle.Bold = true

	a.slotInfo = widget.NewEntry()
	a.slotInfo.MultiLine = true
	a.slotInfo.TextStyle.Monospace = true
	a.slotInfo.Wrapping = fyne.TextWrapOff
	a.slotInfo.Disable()

	slotScroll := container.NewScroll(a.slotInfo)
	slotScroll.SetMinSize(fyne.NewSize(300, 0))

	// Token action buttons
	initBtn := widget.NewButton("Init Token", func() { a.showInitTokenDialog() })
	deleteBtn := widget.NewButton("Delete Token", func() { a.deleteToken() })

	leftPanel := container.NewBorder(
		container.NewVBox(slotLabel, sourceSelect),
		container.NewHBox(initBtn, deleteBtn),
		nil, nil,
		slotScroll,
	)

	// Right panel: objects + PIN
	rightTop := container.NewVBox()

	// PIN entry row
	pinRow := container.NewHBox(
		widget.NewLabel("User PIN:"),
		a.userPINEntry,
		widget.NewButton("Open Session", func() { a.openSession() }),
		widget.NewButton("Close", func() { a.closeSession() }),
	)

	// Objects section
	objLabel := widget.NewLabel("Objects in Token")
	objLabel.TextStyle.Bold = true

	objectsList := widget.NewList(
		func() int { return a.objData.Length() },
		func() fyne.CanvasObject {
			return widget.NewLabel("object")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			if item, _ := a.objData.GetItem(id); item != nil {
				o := item.(hsm.HSMObject)
				l.SetText(fmt.Sprintf("[%s] %s | ID:%x", o.KeyType, o.Label, o.ID))
			}
		},
	)
	objectsList.OnSelected = func(id widget.ListItemID) {
		if item, _ := a.objData.GetItem(id); item != nil {
			o := item.(hsm.HSMObject)
			a.showObjectActions(o)
		}
	}
	a.objectsList = objectsList

	objScroll := container.NewScroll(objectsList)
	objScroll.SetMinSize(fyne.NewSize(0, 200))

	genRSA := widget.NewButton("Generate RSA", func() { a.showGenRSADialog() })
	genEC := widget.NewButton("Generate EC", func() { a.showGenECDialog() })
	importBtn := widget.NewButton("Import PKCS#8", func() { a.showImportDialog() })
	exportBtn := widget.NewButton("Export Public Key", func() { a.exportSelected() })
	deleteBtn2 := widget.NewButton("Delete Object", func() { a.deleteSelected() })

	rightTop = container.NewVBox(
		pinRow,
		objLabel,
		objScroll,
		container.NewHBox(genRSA, genEC, importBtn),
		container.NewHBox(exportBtn, deleteBtn2),
	)

	// Status bar
	a.statusBar = widget.NewLabel("Ready")
	a.statusBar.TextStyle.Monospace = true

	// Split pane
	split := container.NewHSplit(leftPanel, rightTop)
	split.SetOffset(0.35)

	return container.NewBorder(header, a.statusBar, nil, nil, split)
}

// ---- Slot Operations ----

func (a *App) refreshSlots() {
	if a.currentBackend == nil {
		a.setStatus("No backend selected")
		return
	}

	ctx, cancel := context.WithTimeout(a.ctx, 10)
	defer cancel()

	if err := a.currentBackend.Connect(ctx); err != nil {
		a.setStatus(fmt.Sprintf("Connect failed: %v", err))
		return
	}

	slots, err := a.currentBackend.ListSlots(ctx)
	if err != nil {
		a.setStatus(fmt.Sprintf("ListSlots failed: %v", err))
		return
	}

	a.slotData.Set(slots)
	a.slotInfo.SetText("")
	for _, s := range slots {
		info := fmt.Sprintf("Slot %d: %s (init=%v, pin=%v)\n",
			s.SlotID, s.TokenLabel, s.Initialized, s.PINInit)
		a.slotInfo.SetText(a.slotInfo.Text + info)
	}
	a.setStatus(fmt.Sprintf("Loaded %d slot(s)", len(slots)))
}

func (a *App) openSession() {
	slotIDStr := "" // TODO: get from selected slot
	pin := a.userPINEntry.Text
	if pin == "" {
		dialog.ShowInformation("PIN Required", "Enter user PIN first", a.window)
		return
	}

	// Parse selected slot from UI
	// For now, use first slot
	ctx, cancel := context.WithTimeout(a.ctx, 10)
	defer cancel()

	slots, _ := a.currentBackend.ListSlots(ctx)
	if len(slots) == 0 {
		a.setStatus("No slots available")
		return
	}

	if err := a.currentBackend.OpenSession(ctx, slots[0].SlotID, pin); err != nil {
		a.setStatus(fmt.Sprintf("OpenSession failed: %v", err))
		return
	}

	a.loadObjects()
}

func (a *App) closeSession() {
	if a.currentBackend != nil {
		a.currentBackend.CloseSession()
	}
	a.objData.Set(nil)
	a.setStatus("Session closed")
}

func (a *App) loadObjects() {
	ctx, cancel := context.WithTimeout(a.ctx, 15)
	defer cancel()

	objects, err := a.currentBackend.ListObjects(ctx)
	if err != nil {
		a.setStatus(fmt.Sprintf("ListObjects failed: %v", err))
		return
	}

	items := make([]any, len(objects))
	for i := range objects {
		items[i] = objects[i]
	}
	a.objData.Set(items)
	a.setStatus(fmt.Sprintf("Session open — %d object(s)", len(objects)))
}

// ---- Token Operations ----

func (a *App) showInitTokenDialog() {
	labelE := widget.NewEntry()
	soPIN := widget.NewEntry()
	soPIN.Password = true
	userPIN := widget.NewEntry()
	userPIN.Password = true

	form := dialog.NewForm("Initialize Token", "Init", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Token Label", labelE),
			widget.NewFormItem("SO PIN (min 4)", soPIN),
			widget.NewFormItem("User PIN (min 4)", userPIN),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}
			ctx, cancel := context.WithTimeout(a.ctx, 10)
			defer cancel()
			// Find free slot
			slots, _ := a.currentBackend.ListSlots(ctx)
			var freeSlot uint
			for _, s := range slots {
				if !s.Initialized {
					freeSlot = s.SlotID
					break
				}
			}
			err := a.currentBackend.InitToken(ctx, freeSlot, labelE.Text, soPIN.Text, userPIN.Text)
			if err != nil {
				dialog.ShowError(err, a.window)
			}
			a.refreshSlots()
		}, a.window)
	form.Resize(fyne.NewSize(400, 250))
	form.Show()
}

func (a *App) deleteToken() {
	dialog.ShowConfirm("Confirm", "Delete this token? All keys will be lost!",
		func(confirmed bool) {
			if !confirmed {
				return
			}
			ctx, cancel := context.WithTimeout(a.ctx, 10)
			defer cancel()
			slots, _ := a.currentBackend.ListSlots(ctx)
			if len(slots) > 0 {
				a.currentBackend.DeleteToken(ctx, slots[0].SlotID)
				a.refreshSlots()
			}
		}, a.window)
}

// ---- Key Generation ----

func (a *App) showGenRSADialog() {
	labelE := widget.NewEntry()
	idE := widget.NewEntry()
	idE.SetText("01")
	bitsE := widget.NewSelect([]string{"2048", "4096"}, func(s string) {})

	form := dialog.NewForm("Generate RSA Key", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key Label", labelE),
			widget.NewFormItem("Key ID (hex)", idE),
			widget.NewFormItem("Bits", bitsE),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}
			bits, _ := strconv.Atoi(bitsE.Selected)
			id, _ := parseHex(idE.Text)
			ctx, cancel := context.WithTimeout(a.ctx, 30)
			defer cancel()
			err := a.currentBackend.GenerateKey(ctx, hsm.KeyGenParams{
				Label:   labelE.Text,
				ID:      id,
				KeyType: hsm.KeyTypeRSA,
				Bits:    bits,
			})
			if err != nil {
				dialog.ShowError(err, a.window)
				a.setStatus(fmt.Sprintf("GenRSA failed: %v", err))
			} else {
				a.loadObjects()
				a.setStatus("RSA key generated")
			}
		}, a.window)
	form.Show()
}

// ---- Import / Export / Delete ----

func (a *App) showImportDialog() {
	labelE := widget.NewEntry()
	pathE := widget.NewEntry()
	pinE := widget.NewEntry()
	pinE.Password = true

	form := dialog.NewForm("Import PKCS#8", "Import", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key Label", labelE),
			widget.NewFormItem("PKCS#8 File", pathE),
			widget.NewFormItem("File PIN (if encrypted)", pinE),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}
			ctx, cancel := context.WithTimeout(a.ctx, 30)
			defer cancel()
			err := a.currentBackend.ImportKey(ctx, labelE.Text, pathE.Text, pinE.Text)
			if err != nil {
				dialog.ShowError(err, a.window)
			} else {
				a.loadObjects()
				a.setStatus("Key imported")
			}
		}, a.window)
	form.Show()
}

func (a *App) exportSelected() {
	// TODO: get selected object
	dialog.ShowInformation("Export", "Select an object from the list first", a.window)
}

func (a *App) deleteSelected() {
	// TODO: get selected object
	dialog.ShowInformation("Delete", "Select an object from the list first", a.window)
}

// ---- SSH Backend ----

func (a *App) showAddSSHdialog() {
	hostE := widget.NewEntry()
	binaryE := widget.NewEntry()
	binaryE.SetText("softhsm2-util")

	form := dialog.NewForm("Add SSH Remote HSM", "Add", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Host (user@server)", hostE),
			widget.NewFormItem("Binary path", binaryE),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}
			host := strings.TrimSpace(hostE.Text)
			if host == "" {
				return
			}
			be := ssh.NewBackend(host)
			a.backends = append(a.backends, be)
			a.setStatus(fmt.Sprintf("Added SSH backend: %s", be.Name()))
		}, a.window)
	form.Show()
}

// ---- Helpers ----

func (a *App) setStatus(msg string) {
	a.statusBar.SetText(msg)
	log.Println("[softhsm-gui]", msg)
}

func (a *App) showObjectActions(o hsm.HSMObject) {
	dialog.ShowInformation(o.Label,
		fmt.Sprintf("Type: %s / %s\nID: %x", o.Class, o.KeyType, o.ID), a.window)
}

func (a *App) showGenECDialog() {
	labelE := widget.NewEntry()
	idE := widget.NewEntry()
	idE.SetText("01")
	curveE := widget.NewSelect([]string{"secp256r1", "secp384r1", "secp521r1"}, func(s string) {})
	curveE.Selected = "secp256r1"

	form := dialog.NewForm("Generate EC Key", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key Label", labelE),
			widget.NewFormItem("Key ID (hex)", idE),
			widget.NewFormItem("Curve", curveE),
		},
		func(confirmed bool) {
			if !confirmed {
				return
			}
			id, _ := parseHex(idE.Text)
			ctx, cancel := context.WithTimeout(a.ctx, 30)
			defer cancel()
			err := a.currentBackend.GenerateKey(ctx, hsm.KeyGenParams{
				Label:   labelE.Text,
				ID:      id,
				KeyType: hsm.KeyTypeEC,
				Curve:   curveE.Selected,
			})
			if err != nil {
				dialog.ShowError(err, a.window)
				a.setStatus(fmt.Sprintf("GenEC failed: %v", err))
			} else {
				a.loadObjects()
				a.setStatus("EC key generated")
			}
		}, a.window)
	form.Show()
}

func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []byte{0x01}, nil
	}
	return []byte(s), nil
}
