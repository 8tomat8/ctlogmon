package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/8tomat8/ctlogmon/config"
	"github.com/8tomat8/ctlogmon/cttools"
	"github.com/8tomat8/ctlogmon/output"
	"github.com/8tomat8/ctlogmon/state"
	"github.com/sirupsen/logrus"
)

var patternsArg = flag.String("patterns", "", "pass comma separated list of domains that you are interested in")
var verboseArg = flag.Bool("verbose", false, "to print out logs")
var outputArg = flag.String("out", "stdout", "supports file|stdout")

func main() {
	flag.Parse()

	patterns := append([]string{}, strings.Split(*patternsArg, ",")...)
	if *verboseArg {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(0)
	}

	ll, err := cttools.GetLogLists(config.GoogleAllLogsLink)
	if err != nil {
		logrus.Fatal(err)
	}

	var results chan string
	switch *outputArg {
	case "file":
		fn := fmt.Sprintf("latest-%d.txt", time.Now().Unix())
		results, err = output.NewFileOutput(fn)
		fmt.Printf("Sending output to ./%s\n", fn)
	case "stdout":
		results, err = output.NewStdout()
	}
	if err != nil {
		logrus.Fatalf("init output: %w", err)
	}

	for _, list := range ll {
		list := list
		go func() {
			cli, err := cttools.GetLogClient(list.URL, list.Key)
			if err != nil {
				logrus.Fatal(fmt.Errorf("create log access client: %s", err))
			}
			pageSize := config.GetPageSize(list.URL)

			treeSize, err := cttools.GetTreeSize(cli)
			if err != nil {
				logrus.Warn(err)
				return
			}
			state.Set(list.URL, treeSize)

			ticker := time.NewTicker(time.Second * 10)

			for range ticker.C {
				curState := state.Get(list.URL)

				newTreeSize, err := cttools.GetTreeSize(cli)
				if err != nil {
					logrus.Warn(err)
					continue
				}

				for i := curState; i < newTreeSize; i += pageSize {
					start, end := i, i+pageSize
					if end > newTreeSize {
						end = newTreeSize
					}
					logrus.Infof("start: %d | end: %d", start, end)
					entities, err := cli.GetEntries(context.Background(), start, end)
					if err != nil {
						logrus.Infof("get enteties: %s", err)
						continue
					}
					for _, ent := range entities {
						crt, _ := ent.Leaf.X509Certificate()
						if crt == nil {
							continue
						}

						for _, p := range patterns {
							if strings.Contains(crt.Subject.CommonName, p) {
								results <- crt.Subject.CommonName
							}
						}
					}

					state.Set(list.URL, end)
				}

				ticker.Reset(time.Second * 10)
			}
		}()
	}

	handleSignals() //blocking

}

func handleSignals() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Waiting for the first signal
	<-sigs
}
