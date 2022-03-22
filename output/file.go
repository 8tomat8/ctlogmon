package output

import (
	"fmt"
	"os"
)

var OutputChannelSize = 1000

func NewFileOutput(name string) (chan<- string, error) {
	input := make(chan string, OutputChannelSize)

	f, err := os.OpenFile(fmt.Sprintf("./%s", name), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("can not open/create a file: %w", err)
	}
	go func() {
		defer f.Close()

		for dom := range input {
			f.WriteString(dom + "\n")
		}
	}()
	return input, nil
}
