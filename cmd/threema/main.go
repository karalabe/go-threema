// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/karalabe/go-threema"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	identityFlag        string
	passwordFlag        string
	recipientIDFlag     string
	recipientPubKeyFlag string
	messageTextFlag     string
	messageImageFlag    string
)

func main() {
	viper.AutomaticEnv()

	// Prepare the commansd for sending messages
	cmdSendText := &cobra.Command{
		Use:   "text",
		Short: "Send a text message to a Threema user",
		Run:   sendText,
	}
	cmdSendText.Flags().StringVar(&identityFlag, "id", viper.GetString("THREEMA_ID_BACKUP"), "Exported and password protected Threema identity (THREEMA_ID_BACKUP)")
	cmdSendText.Flags().StringVar(&passwordFlag, "id.secret", viper.GetString("THREEMA_ID_SECRET"), "Decryption password used to export the identity (THREEMA_ID_SECRET)")
	cmdSendText.Flags().StringVar(&recipientIDFlag, "to", "", "Threema ID to send a message to")
	cmdSendText.Flags().StringVar(&recipientPubKeyFlag, "to.pubkey", "", "Threema public key of the recipient (optional)")
	cmdSendText.Flags().StringVar(&messageTextFlag, "msg", "", "Text message to send to the recipient")

	cmdSendText.MarkFlagRequired("to")
	cmdSendText.MarkFlagRequired("msg")

	cmdSendImage := &cobra.Command{
		Use:   "image",
		Short: "Send an image to a Threema user",
		Run:   sendImage,
	}
	cmdSendImage.Flags().StringVar(&identityFlag, "id", viper.GetString("THREEMA_ID_BACKUP"), "Exported and password protected Threema identity (THREEMA_ID_BACKUP)")
	cmdSendImage.Flags().StringVar(&passwordFlag, "id.secret", viper.GetString("THREEMA_ID_SECRET"), "Decryption password used to export the identity (THREEMA_ID_SECRET)")
	cmdSendImage.Flags().StringVar(&recipientIDFlag, "to", "", "Threema ID to send a message to")
	cmdSendImage.Flags().StringVar(&recipientPubKeyFlag, "to.pubkey", "", "Threema public key of the recipient (optional)")
	cmdSendImage.Flags().StringVar(&messageImageFlag, "img", "", "Image file path to send to the recipient")
	cmdSendImage.Flags().StringVar(&messageTextFlag, "msg", "", "Image caption to send to the recipient")

	cmdSendImage.MarkFlagRequired("to")
	cmdSendImage.MarkFlagRequired("img")

	cmdSend := &cobra.Command{
		Use:   "send",
		Short: "Send a message to a Threema user",
	}
	cmdSend.AddCommand(cmdSendText, cmdSendImage)

	// Prepare the administrative commands
	cmdExport := &cobra.Command{
		Use:   "export",
		Short: "Re-export a Threema backup with a new password",
		Run:   exportBackup,
	}
	rootCmd := &cobra.Command{Use: "threema"}
	rootCmd.AddCommand(cmdSend, cmdExport)
	rootCmd.Execute()
}

func sendText(cmd *cobra.Command, args []string) {
	// Construct the sender identity with the recipient contact
	id := makeIdentity()

	// Connect to the Threema network and send the message
	log.Println("Connecting to the Threeman network")
	conn, err := threema.Connect(id, new(threema.Handler)) // Ignore message
	if err != nil {
		log.Fatalf("Failed to connect to the Threema network: %v", err)
	}
	defer conn.Close()

	log.Println("Sending text message")
	if err := conn.SendText(recipientIDFlag, messageTextFlag); err != nil {
		log.Fatalf("Failed to send text message: %v", err)
	}
	log.Println("Message sent.")

	time.Sleep(5 * time.Second)
}

func sendImage(cmd *cobra.Command, args []string) {
	// Construct the sender identity with the recipient contact
	id := makeIdentity()

	// Load the image blob from disk
	blob, err := ioutil.ReadFile(messageImageFlag)
	if err != nil {
		log.Fatalf("Failed to load the image to send: %v", err)
	}
	// Connect to the Threema network and send the image
	log.Println("Connecting to the Threeman network")
	conn, err := threema.Connect(id, new(threema.Handler)) // Ignore message
	if err != nil {
		log.Fatalf("Failed to connect to the Threema network: %v", err)
	}
	defer conn.Close()

	log.Println("Sending image message")
	if err := conn.SendImage(recipientIDFlag, blob, messageTextFlag); err != nil {
		log.Fatalf("Failed to send image message: %v", err)
	}
	log.Println("Message sent.")
}

func exportBackup(cmd *cobra.Command, args []string) {
	// Try to load the previously encrypted identity
	id, err := threema.Identify(identityFlag, passwordFlag)
	if err != nil {
		log.Fatalf("Failed to load sender identity: %v", err)
	}
	fmt.Printf("Re-exporting identity: %s\n\n", identityFlag)

	// Read the new password from the user and confirm it
	fmt.Printf("Please enter new export password: ")
	secret, err := term.ReadPassword(0)
	if err != nil {
		log.Fatalf("Failed to read new password: %v", err)
	}
	fmt.Println()

	fmt.Printf("Please confirm new export password: ")
	confirm, err := term.ReadPassword(0)
	if err != nil {
		log.Fatalf("Failed to confirm new password: %v", err)
	}
	fmt.Println()

	if !bytes.Equal(secret, confirm) {
		log.Fatalf("Entered password and confirmation do not match")
	}
	fmt.Println()

	// Export the identity with the new password and sanity check that we can
	// load it back up.
	export, err := id.Export(string(secret))
	if err != nil {
		log.Fatalf("Failed to export identity: %v", err)
	}
	fmt.Printf("Re-exported identity: %s\n\n", export)
	fmt.Println(
		"If you are using this tool with environment variables for setting the identity\n" +
			"and import secret (THREEMA_ID_BACKUP and THREEMA_ID_SECRET), you will need to\n" +
			"re-set those variables to use the newly exported identity backups.",
	)
}

// makeIdentity constructs the sender identity with the recipient as a contact
// based on the provided CLI flags.
func makeIdentity() *threema.Identity {
	log.Println("Loading local and remote identity")
	id, err := threema.Identify(identityFlag, passwordFlag)
	if err != nil {
		log.Fatalf("Failed to load sender identity: %v", err)
	}
	if recipientPubKeyFlag == "" {
		log.Println("Recipient key not provided, looking up")
		pubkey, err := lookupPubkey(recipientIDFlag)
		if err != nil {
			log.Fatalf("Failed to retrieve recipient public key: %v", err)
		}
		recipientPubKeyFlag = pubkey
	}
	if err := id.Trust(recipientIDFlag, recipientPubKeyFlag); err != nil {
		log.Fatalf("Failed to add recipient as contact: %v", err)
	}
	return id
}
