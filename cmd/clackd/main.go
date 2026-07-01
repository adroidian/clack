package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/adroidian/clack/internal/store"
)

func main() {
	dbPath := flag.String("db", "clack.db", "SQLite database path")
	addr := flag.String("addr", "127.0.0.1:0", "HTTP listen address")
	once := flag.Bool("once", false, "initialize database and exit")
	flag.Parse()

	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	if err := s.Init(); err != nil {
		log.Fatal(err)
	}
	if *once {
		fmt.Printf("clackd initialized %s\n", *dbPath)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"clackd","mode":"local-only"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "clackd listening on %s db=%s\n", *addr, *dbPath)
	log.Fatal(srv.ListenAndServe())
}
