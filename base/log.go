package base

import (
	"github.com/op/go-logging"
)

var logger *logging.Logger

func Logger() *logging.Logger {
	if logger == nil {
		logger = logging.MustGetLogger("Garin")
		var backend1, _ = logging.NewSyslogBackend("garin")
		var backend1Leveled = logging.AddModuleLevel(backend1)
		backend1Leveled.SetLevel(logging.INFO, "")
		logging.SetBackend(backend1Leveled)
	}
	return logger
}

func Die(args ...interface{}) {
	Logger().Critical(args...)
	panic(args)
}
