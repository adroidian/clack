package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/adroidian/clack/internal/store"
)

func usage() {
	fmt.Fprintf(os.Stderr, `clackctl --db clack.db <command> [args]

Commands:
  agent register <agentId> [--name name]
  dm send <from> <to> <body>
  inbox list <agentId>
  channel create <name>
  channel post <channel> <from> <body>
  receipt list
`)
	os.Exit(2)
}

func main() {
	dbPath := flag.String("db", "clack.db", "SQLite database path")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	s, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	if err := s.Init(); err != nil {
		log.Fatal(err)
	}

	switch args[0] {
	case "agent":
		if len(args) < 3 || args[1] != "register" {
			usage()
		}
		name := ""
		fs := flag.NewFlagSet("agent register", flag.ExitOnError)
		fs.StringVar(&name, "name", "", "display/short name")
		_ = fs.Parse(args[3:])
		a, err := s.RegisterAgent(args[2], name)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("registered %s name=%s\n", a.AgentID, a.Name)
	case "dm":
		if len(args) < 5 || args[1] != "send" {
			usage()
		}
		msg, receipts, err := s.SendDM(args[2], args[3], strings.Join(args[4:], " "))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("dm %s %s -> %s\n", msg.ID, msg.FromAgent, msg.ToAgent)
		for _, r := range receipts {
			if err := printReceipt(r); err != nil {
				log.Fatal(err)
			}
		}
	case "inbox":
		if len(args) != 3 || args[1] != "list" {
			usage()
		}
		items, err := s.ListInbox(args[2])
		if err != nil {
			log.Fatal(err)
		}
		for _, it := range items {
			fmt.Printf("%s %s <- %s %s\n", it.ID, it.AgentID, it.FromAgent, it.Body)
		}
	case "channel":
		if len(args) < 3 {
			usage()
		}
		switch args[1] {
		case "create":
			ch, err := s.CreateChannel(args[2])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("channel %d %s\n", ch.ID, ch.Name)
		case "post":
			if len(args) < 5 {
				usage()
			}
			msg, receipts, err := s.PostChannel(args[2], args[3], strings.Join(args[4:], " "))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("channel-post %s channel=%s from=%s\n", msg.ID, msg.ChannelName, msg.FromAgent)
			for _, r := range receipts {
				if err := printReceipt(r); err != nil {
					log.Fatal(err)
				}
			}
		default:
			usage()
		}
	case "receipt":
		if len(args) != 2 || args[1] != "list" {
			usage()
		}
		receipts, err := s.ListReceipts()
		if err != nil {
			log.Fatal(err)
		}
		for _, r := range receipts {
			if err := printReceipt(r); err != nil {
				log.Fatal(err)
			}
		}
	default:
		usage()
	}
}

func printReceipt(r store.Receipt) error {
	payload, err := r.JSON()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", payload)
	return nil
}
