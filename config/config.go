package config

import "strings"

const GoogleAllLogsLink = "https://www.gstatic.com/ct/log_list/all_logs_list.json"

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

func GetPageSize(url string) int64 {
	for pat, v := range pageSizes {
		if strings.Contains(url, pat) {
			return v
		}
	}
	return 32
}
