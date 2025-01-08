package main

import (
	"log"
	"os"

	"github.com/lsongdev/imap-go/imap"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	client, err := imap.NewClient()
	check(err)

	err = client.Connect("imap.gmail.com", 993)
	check(err)
	defer client.Close()

	username := os.Getenv("IMAP_USERNAME")
	password := os.Getenv("IMAP_PASSWORD")
	client.Login(username, password)
	defer client.Logout()

	folders, err := client.GetFolders()
	check(err)

	// folders = []string{
	// 	"INBOX",
	// 	"INBOX/My Folder"
	// 	"Sent Items",
	// 	"Deleted",
	// }

	// Now we can loop through those folders
	for _, f := range folders {
		log.Println("Mailbox:", f)
	}

	err = client.SelectFolder("INBOX")
	check(err)

	// This function implements the IMAP UID search, returning a slice of ints
	// Sending "ALL" runs the command "UID SEARCH ALL"
	// You can enter things like "*:1" to get the first UID, or "999999999:*"
	// to get the last (unless you actually have more than that many emails)
	// You can check out https://tools.ietf.org/html/rfc3501#section-6.4.4 for more
	filter := imap.SearchFilter{
		WithoutFlags: []string{imap.FlagSeen},
	}
	uids, err := client.Search(filter.String())
	check(err)

	// uids = []int{1, 2, 3}
	emails, err := client.GetEmails(uids...)
	check(err)

	for _, e := range emails {
		log.Println(e.Subject)
	}
}
