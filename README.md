# ctlogmon

Run
```bash
go run ./cmd/latest/main.go | grep domain.com
```
or
```bash
go run ./cmd/latest/main.go -patterns domain.com,another.nl,one-more.cc
```

Script will create a file named `latest-[timestemp].txt`. 1 domain per line per issued certificate since script start.
