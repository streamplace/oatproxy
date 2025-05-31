package oatproxy

import (
	"sync"
)

// NamedLocks provides a way to get a mutex for a given name/key
type NamedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewNamedLocks creates a new NamedLocks instance
func NewNamedLocks() *NamedLocks {
	return &NamedLocks{
		locks: make(map[string]*sync.Mutex),
	}
}

// GetLock returns the mutex for the given name, creating it if it doesn't exist
func (n *NamedLocks) GetLock(name string) *sync.Mutex {
	n.mu.Lock()
	defer n.mu.Unlock()

	lock, exists := n.locks[name]
	if !exists {
		lock = &sync.Mutex{}
		n.locks[name] = lock
	}
	return lock
}
