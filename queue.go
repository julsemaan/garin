package main

import (
	"sync"
)

type Queue struct {
	queue      []interface{}
	queueMutex *sync.Mutex
}

func NewQueue() *Queue {
	queue := &Queue{}
	queue.queue = make([]interface{}, 0)
	queue.queueMutex = &sync.Mutex{}
	return queue
}

func (self *Queue) push(o interface{}) {
	self.queueMutex.Lock()
	self.queue = append(self.queue, o)
	self.queueMutex.Unlock()
}

func (self *Queue) shift() interface{} {
	self.queueMutex.Lock()
	var o interface{}
	if len(self.queue) > 0 {
		o, self.queue = self.queue[0], self.queue[1:]
	}
	self.queueMutex.Unlock()
	return o
}

func (self *Queue) empty() bool {
	return len(self.queue) == 0
}
