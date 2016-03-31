package main

import (
	"github.com/julsemaan/WebSniffer/log"
	"sync"
)

type RecordingQueue struct {
	db                     *WebSnifferDB
	destinationsQueue      []*Destination
	destinationsQueueMutex *sync.Mutex
}

func (self *RecordingQueue) push(destination *Destination) {
	self.destinationsQueueMutex.Lock()
	self.destinationsQueue = append(self.destinationsQueue, destination)
	self.destinationsQueueMutex.Unlock()
}

func (self *RecordingQueue) shift() *Destination {
	self.destinationsQueueMutex.Lock()
	var destination *Destination
	if len(self.destinationsQueue) > 0 {
		destination, self.destinationsQueue = self.destinationsQueue[0], self.destinationsQueue[1:]
	}
	self.destinationsQueueMutex.Unlock()
	return destination
}

func (self *RecordingQueue) empty() bool {
	return len(self.destinationsQueue) == 0
}

func NewRecordingQueue() *RecordingQueue {
	recording_queue := &RecordingQueue{}
	recording_queue.db = GetDB()
	recording_queue.destinationsQueue = make([]*Destination, 0)
	recording_queue.destinationsQueueMutex = &sync.Mutex{}
	return recording_queue
}

func (self *RecordingQueue) work() bool {
	destination := self.shift()
	if destination != nil {
		destination.Save(self.db)
		return true
	}
	return false
}
