package main

import (
	"log"

	"github.com/andrewchanlab/softhsm-gui/internal/ui"
	_ "github.com/andrewchanlab/softhsm-gui/internal/hsm/local"
	_ "github.com/andrewchanlab/softhsm-gui/internal/hsm/ssh"
)

func main() {
	log.SetFlags(0)
	app := ui.NewApp()
	app.Run()
}
