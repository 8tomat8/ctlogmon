package cttools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/sirupsen/logrus"
)

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

func GetLogClient(url string, key []byte) (*client.LogClient, error) {
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

type Log struct {
	Key []byte `json:"key"`
	URL string `json:"url"`
}

func GetLogLists(allLogsLink string) ([]Log, error) {
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

func GetTreeSize(cli *client.LogClient) (int64, error) {
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
