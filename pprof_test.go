package scanner

import (
	"net/http"
	_ "net/http/pprof"
)

func pprof() {
	go func() { _ = http.ListenAndServe(":8080", nil) }()
}
