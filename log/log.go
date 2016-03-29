package log

import (
	"github.com/op/go-logging"
	"os"
)

var logger *logging.Logger

func Logger() *logging.Logger {
	if logger == nil {
		logger = logging.MustGetLogger("WebSniffer")
		var backend1 = logging.NewLogBackend(os.Stderr, "", 0)
		var backend1Leveled = logging.AddModuleLevel(backend1)
		backend1Leveled.SetLevel(logging.INFO, "")
		logging.SetBackend(backend1Leveled)
	}
	return logger
}
