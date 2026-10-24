package main

import (
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/service"
)

// Function fields so tests can swap in a fake init system.
type serviceAPI struct {
	isInstalled  func() bool
	status       func() service.ServiceStatus
	install      func(binPath string, port int, host string) ([]string, error)
	writeFile    func(binPath string, port int, host string) ([]string, error)
	fileMatches  func(binPath string, port int, host string) (bool, error)
	start        func() error
	stop         func() error
	uninstall    func() error
	waitHealthy  func(host string, port int, timeout time.Duration) error
	healthCheck  func(host string, port int) error
	lingerStatus func() (enabled, known bool)
}

var svc = realService()

func realService() serviceAPI {
	return serviceAPI{
		isInstalled:  service.IsInstalled,
		status:       service.GetStatus,
		install:      service.Install,
		writeFile:    service.WriteServiceFile,
		fileMatches:  service.ServiceFileMatches,
		start:        service.Start,
		stop:         service.Stop,
		uninstall:    service.Uninstall,
		waitHealthy:  service.WaitHealthy,
		healthCheck:  service.HealthCheck,
		lingerStatus: service.LingerStatus,
	}
}
