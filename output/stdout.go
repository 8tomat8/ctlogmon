package output

import (
	"os"
)

func NewStdout() (chan string, error) {
	input := make(chan string, OutputChannelSize)

	go func() {
		for dom := range input {
			os.Stdout.WriteString(dom + "\n")
		}
	}()
	return input, nil
}
