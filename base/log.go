package base

import (
	"fmt"
	"github.com/op/go-logging"
)

var logger *logging.Logger
var loggerBackend logging.Backend

func LoggerWithLevel(levelStr string) *logging.Logger {
	Logger()
	level, err := logging.LogLevel(levelStr)
	if err != nil {
		fmt.Println("Cannot find log level : " + levelStr)
	}
	leveledBackend := logging.AddModuleLevel(loggerBackend)
	leveledBackend.SetLevel(level, "")
	logging.SetBackend(leveledBackend)
	return Logger()
}

func Logger() *logging.Logger {
	if logger == nil {
		logger = logging.MustGetLogger("Garin")
		loggerBackend, _ = logging.NewSyslogBackend("garin")
		logging.SetBackend(loggerBackend)
	}
	return logger
}

func Die(args ...interface{}) {
	Logger().Critical(args...)
	panic("Application issue. Check logs for details.")
}
