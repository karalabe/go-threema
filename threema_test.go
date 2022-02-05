// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema_test

import (
	"fmt"
	"time"

	"github.com/karalabe/go-threema"
)

func ExampleIdentify() {
	// We assume you already have an exported identity (don't get your hopes up,
	// this is a fake identity).
	var (
		backup   = "A4G3-BF25-JEN4-EA7Q-XSMG-AIYL-A2W6-CCTW-VYGW-HT3L-KVA7-TTG7-VF2G-RHMY-YB5I-ER7S-WQMU-XF4Y-PZLU-XJFN"
		password = "1337speak"
	)
	// Loading an exported identity is as simple as providing the exported backup
	// string and the password it was encrypted with.
	id, err := threema.Identify(backup, password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded Threema identity: %s\n", id.Self())
}

func ExampleConnect() {
	// We assume you already loaded an exported identity though this library, as
	// well as a handler that reacts to events. Mode on this later.
	var (
		id      *threema.Identity
		handler *threema.Handler
	)
	// With a real identity and an event handler (you can use nil for a dry run),
	// it's already enough to authenticate into the Threema network.
	conn, err := threema.Connect(id, handler)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Printf("Connected to the Threema network\n")
}

func ExampleHandler() {
	// There are various events that a user might want to react to. These are
	// most commonly messages received from others, but there are also a few
	// Threema protocol events too.
	handler := &threema.Handler{
		Message: func(from string, nick string, when time.Time, msg string) {
			fmt.Printf("%v] %s(%s): %s\n", when, from, nick, msg)
		},
	}
	fmt.Printf("Handler methods implemented: %+v\n", handler)
}

func ExampleMessage() {
	// We assume you already loaded an exported identity though this library, as
	// well as established a live connection to the Threema servers.
	var (
		id   *threema.Identity
		conn *threema.Connection
	)
	// Sending a message will block until it is delivered to the Threema servers
	// and it is acknowledged by it (i.e. no data loss). There is no waiting for
	// the remote side to receive nor read it!
	if err := conn.SendText(id.Self(), "Hello Threema!"); err != nil {
		panic(err)
	}
	fmt.Printf("We've just sent out first message!\n")
}

func ExampleTrust() {
	// We assume you already loaded an exported identity though this library, as
	// well as retrieved a known user's base64 encoded public key from Threema's
	// user directory service.
	var (
		id *threema.Identity

		friend = "DEADBEEF"
		pubkey = "1qEnvgAm59YN0VUQqjOWHF3TymgIcIdMDpH7p1GajQU="
	)
	// Add the friend's key mapped to their Threema ID.
	if err := id.Trust(friend, pubkey); err != nil {
		panic(err)
	}
	fmt.Printf("We've just trusted %s to message with\n", friend)
}
