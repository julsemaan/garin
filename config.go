package main

import (
	"github.com/julsemaan/WebSniffer/log"
	"gopkg.in/gcfg.v1"
)

type Config struct {
	General struct {
		Parsing_concurrency      int
		Recording_threads        int
		Dont_record_destinations bool
	}
	Capture struct {
		Interface               string
		Unencrypted_ports       string
		Encrypted_ports         string
		Snaplen                 int
		Buffered_per_connection int
		Total_max_buffer        int
		Flush_after             string
	}
}

func NewConfig(filename string) *Config {
	cfg := &Config{}
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		log.Die("Failed to parse gcfg", err)
	}
	return cfg
}
