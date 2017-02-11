package main

import (
	"testing"
)

func TestQueuePushShift(t *testing.T) {
	q := NewQueue()
	s1 := "test"
	q.Push(s1)

	if len(q.queue) != 1 {
		t.Errorf("Queue length is incorrect after push %d instead of 1", len(q.queue))
	}

	if q.queue[0] != s1 {
		t.Errorf("Value in queue isn't correct %s instead of %s", q.queue[0], s1)
	}

	s2 := "test2"
	q.Push(s2)

	if len(q.queue) != 2 {
		t.Errorf("Queue length is incorrect after push %d instead of 2", len(q.queue))
	}

	if q.queue[1] != s2 {
		t.Errorf("Value in queue isn't correct %s instead of %s", q.queue[1], s2)
	}

	res := q.Shift()

	if len(q.queue) != 1 {
		t.Errorf("Queue length is incorrect after push %d instead of 1", len(q.queue))
	}

	if res != s1 {
		t.Error("Element that was dequeued doesn't have the right value. %s instead of %s", res, s1)
	}

	res = q.Shift()

	if len(q.queue) != 0 {
		t.Errorf("Queue length is incorrect after push %d instead of 0", len(q.queue))
	}

	if res != s2 {
		t.Error("Element that was dequeued doesn't have the right value. %s instead of %s", res, s2)
	}
}

func TestQueueEmpty(t *testing.T) {
	q := NewQueue()

	for i := 0; i < 5; i++ {
		q.Push("")
	}

	if q.IsEmpty() {
		t.Error("Queue reports as empty when its not")
	}

	for i := 0; i < 5; i++ {
		q.Shift()
	}

	if !q.IsEmpty() {
		t.Error("Queue doesn't report as empty when it is")
	}

}
