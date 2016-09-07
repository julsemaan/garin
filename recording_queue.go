package main

import (
	"github.com/julsemaan/garin/base"
	"sync"
	"time"
)

type DebouncedRecording struct {
	lastSave    time.Time
	destination *base.Destination
}

type RecordingQueue struct {
	dummy             bool
	queue             *Queue
	debouncedQueue    *Queue
	DebounceThreshold time.Duration
	debounceMap       map[string]*DebouncedRecording
	debounceMutex     *sync.Mutex
}

func NewRecordingQueue() *RecordingQueue {
	recording_queue := &RecordingQueue{}
	recording_queue.queue = NewQueue()
	recording_queue.debouncedQueue = NewQueue()
	recording_queue.debounceMutex = &sync.Mutex{}
	recording_queue.dummy = false
	return recording_queue
}

func (self *RecordingQueue) push(destination *base.Destination) {
	self.queue.push(destination)
}

func (self *RecordingQueue) empty() bool {
	return self.queue.empty() && self.debouncedQueue.empty()
}

func (self *RecordingQueue) _shift(queue *Queue) *base.Destination {
	o := queue.shift()
	if o == nil {
		return nil
	}
	destination, ok := o.(*base.Destination)
	if !ok {
		panic("Element in queue wasn't a destination")
	}
	return destination
}

func (self *RecordingQueue) shift() *base.Destination {
	return self._shift(self.queue)
}

func (self *RecordingQueue) shiftDebounced() *base.Destination {
	return self._shift(self.debouncedQueue)
}

func (self *RecordingQueue) SetDebounceThreshold(debounceThreshold time.Duration) {
	Logger().Debugf("Debounce threshold set to %s", debounceThreshold)
	if debounceThreshold.Seconds() != 0 {
		self.DebounceThreshold = debounceThreshold
		self.debounceMap = make(map[string]*DebouncedRecording)
		go func() {
			tickSeconds := debounceThreshold / 2
			Logger().Infof("Debounce worker will run every %s", tickSeconds)
			tick := time.Tick(tickSeconds)
			for _ = range tick {
				self.workDebounceMap()
			}
		}()
	}
}

func (self *RecordingQueue) workDebounceMap() {
	Logger().Debug("Working debounce map")
	self.debounceMutex.Lock()
	defer self.debounceMutex.Unlock()
	var toDelete []string
	for hash, info := range self.debounceMap {
		if info.lastSave.Unix()+int64(self.DebounceThreshold.Seconds()) > time.Now().Unix() {
			Logger().Debugf("Entry %s is ready to be saved", hash)
			self.debouncedQueue.push(info.destination)
			toDelete = append(toDelete, hash)
		}
	}
	for _, hash := range toDelete {
		Logger().Debugf("Removing %s from debounce map", hash)
		delete(self.debounceMap, hash)
	}
	Logger().Debug("Done working debounce map")
}

func (self *RecordingQueue) saveWithDebounce(destination *base.Destination, db base.GarinDB) {
	if self.DebounceThreshold != 0 {
		self.debounceMutex.Lock()
		defer self.debounceMutex.Unlock()
		hash := destination.Hash()
		info := self.debounceMap[hash]
		if info != nil {
			Logger().Debug("Updating entry in debounce map")
			self.debounceMap[hash].lastSave = time.Now()
		} else {
			Logger().Debug("Creating entry in debounce map")
			self.debounceMap[hash] = &DebouncedRecording{time.Now(), destination}
		}
	} else {
		destination.Save(db)
	}
}

func (self *RecordingQueue) work(db base.GarinDB) bool {
	worked := false
	destination := self.shift()
	if destination != nil {
		self.saveWithDebounce(destination, db)
		worked = true
	}
	destination = self.shiftDebounced()
	if destination != nil {
		destination.Save(db)
		worked = true
	}
	return worked
}
