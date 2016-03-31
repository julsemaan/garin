package main

import (
	"sync"
)

type RecordingQueue struct {
	queue      []*Destination
	queueMutex *sync.Mutex
}

func (self *RecordingQueue) push(destination *Destination) {
	self.queueMutex.Lock()
	self.queue = append(self.queue, destination)
	self.queueMutex.Unlock()
}

func (self *RecordingQueue) shift() *Destination {
	self.queueMutex.Lock()
	var destination *Destination
	if len(self.queue) > 0 {
		destination, self.queue = self.queue[0], self.queue[1:]
	}
	self.queueMutex.Unlock()
	return destination
}

func (self *RecordingQueue) empty() bool {
	return len(self.queue) == 0
}

func NewRecordingQueue() *RecordingQueue {
	recording_queue := &RecordingQueue{}
	recording_queue.queue = make([]*Destination, 0)
	recording_queue.queueMutex = &sync.Mutex{}
	return recording_queue
}

func (self *RecordingQueue) work(db *WebSnifferDB) bool {
	destination := self.shift()
	if destination != nil {
		destination.Save(db)
		return true
	}
	return false
}
