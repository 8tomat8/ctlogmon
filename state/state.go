package state

import "sync"

var (
	lag   = map[string]int64{}
	lagMU = &sync.RWMutex{}
)

func Get(url string) int64 {
	lagMU.RLock()
	defer lagMU.RUnlock()

	return lag[url]
}

func Set(url string, state int64) {
	lagMU.Lock()
	defer lagMU.Unlock()

	lag[url] = state
}
