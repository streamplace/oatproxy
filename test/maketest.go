package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bluesky-social/indigo/api/atproto"
	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/xrpc"
)

func main() {
	email := "test@test.com"
	password := "test"
	c := &xrpc.Client{
		Host: "http://localhost:39091",
	}

	out, err := comatproto.ServerCreateAccount(context.Background(), c, &atproto.ServerCreateAccount_Input{
		Email:    &email,
		Password: &password,
		Handle:   "oatproxy.test",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(out)
}
