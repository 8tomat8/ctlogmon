package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sirupsen/logrus"
)

const allLogsLink = "https://www.gstatic.com/ct/log_list/all_logs_list.json"

type Log struct {
	Key []byte `json:"key"`
	URL string `json:"url"`
}

var pageSizes = map[string]int64{
	"googleapis":                         32,
	"cloudflare":                         1024,
	"digicert":                           256,
	"comodo":                             1000,
	"oak.ct.letsencrypt.org/2019/":       32,
	"oak.ct.letsencrypt.org/2020/":       32,
	"oak.ct.letsencrypt.org/2021/":       256,
	"oak.ct.letsencrypt.org/2022/":       256,
	"oak.ct.letsencrypt.org/2023/":       256,
	"testflume.ct.letsencrypt.org/2020/": 256,
	"testflume.ct.letsencrypt.org/2021/": 256,
	"testflume.ct.letsencrypt.org/2022/": 256,
	"testflume.ct.letsencrypt.org/2023/": 256,
	"trustasia":                          256,
}

func getPageSize(url string) int64 {
	for pat, v := range pageSizes {
		if strings.Contains(url, pat) {
			return v
		}
	}
	return 32
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	},
}

func getLogClient(url string, key []byte) (*client.LogClient, error) {
	opts := jsonclient.Options{
		UserAgent:    "ct-go-ctclient/1.0",
		PublicKeyDER: key,
	}

	logClient, err := client.New(url, httpClient, opts)
	if err != nil {
		return nil, err
	}
	logClient.Verifier = nil
	return logClient, nil
}

func getLogLists() ([]Log, error) {
	rsp, err := httpClient.Get(allLogsLink)
	if err != nil {
		return nil, fmt.Errorf("fetching all log lists: %s", err)
	}

	ll := &struct {
		Logs []Log `json:"logs`
	}{}
	err = json.NewDecoder(rsp.Body).Decode(ll)
	if err != nil {
		return nil, fmt.Errorf("parse log lists: %s", err)
	}

	// validate format and add schema
	for i, list := range ll.Logs {
		u, err := url.Parse(list.URL)
		if err != nil {
			logrus.Errorf("parse log list url: %s", err)
			continue
		}
		u.Scheme = "https"
		ll.Logs[i].URL = u.String()
	}

	return ll.Logs, nil
}

func getTreeSize(cli *client.LogClient) (int64, error) {
	head, err := cli.GetSTH(context.Background())
	if err != nil {
		return 0, fmt.Errorf("get STH for %s: %s", cli.BaseURI(), err)
	}

	treeSize := int64(head.TreeSize) // Gods save me
	if uint64(treeSize) != head.TreeSize {
		return 0, errors.New("fuck my life")
	}
	return treeSize, nil
}

var (
	lag   = map[string]int64{}
	lagMU = &sync.RWMutex{}
)

func getState(url string) int64 {
	lagMU.RLock()
	defer lagMU.RUnlock()

	return lag[url]
}

func setState(url string, state int64) {
	lagMU.Lock()
	defer lagMU.Unlock()

	lag[url] = state
}

func main() {
	ll, err := getLogLists()
	if err != nil {
		logrus.Fatal(err)
	}

	domains := make(chan string, 1000)
	go func() {
		f, err := os.OpenFile(fmt.Sprintf("./latest-%d.txt", time.Now().Unix()), os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			logrus.Fatal("well... fuck you!")
		}
		defer f.Close()

		for dom := range domains {
			f.WriteString(dom + "\n")
		}
	}()

	for _, list := range ll {
		list := list
		go func() {
			cli, err := getLogClient(list.URL, list.Key)
			if err != nil {
				logrus.Fatal(fmt.Errorf("create log access client: %s", err))
			}
			pageSize := getPageSize(list.URL)

			treeSize, err := getTreeSize(cli)
			if err != nil {
				logrus.Error(err)
				return
			}
			setState(list.URL, treeSize)

			ticker := time.NewTicker(time.Second * 10)

			for range ticker.C {
				curState := getState(list.URL)

				newTreeSize, err := getTreeSize(cli)
				if err != nil {
					logrus.Error(err)
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

						domains <- crt.Subject.CommonName
					}

					setState(list.URL, end)
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
