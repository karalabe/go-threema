// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// cookieLength is the length of the randomly generated nonce prefix
	cookieLength = 16
)

// Connection represents a live connection to the Threema servers, authenticated
// with a pre-loaded Threema personal user.
type Connection struct {
	id      *Identity // User identity for encryption and decryption
	handler *Handler  // User handler for inbound system and user messages

	conn net.Conn // Live connection to the Threema server

	clientNonce *nonce // Nonce used to encrypt client packets
	serverNonce *nonce // Nonce used to decrypt server packets

	clientKey *[secretLength]byte // Session private key to decrypt server messages with
	serverKey *[publicLength]byte // Session public key to encrypt client messages with

	readerDown chan struct{} // Channel to signal that the connection dropped (signal app)
	senderDown chan struct{} // Channel to signal that the sender aborted (unblock sends)

	sendAckCh   chan *messageAck   // Channel for sending a message ack to Threema
	sendTextCh  chan *sendTextReq  // Channel to send a text message to Threema
	sendImageCh chan *sendImageReq // Channel to send an image message to Threema
}

// Connect dials the Threema servers and runs the authentication handshake.
func Connect(id *Identity, handler *Handler) (*Connection, error) {
	// Establish the unsecure TCP connection to Threema
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", chatServerPrefixV4+chatServerGroup+chatServerSuffix, chatServerPort))
	if err != nil {
		return nil, err
	}
	c := &Connection{
		id:          id,
		handler:     handler,
		conn:        conn,
		readerDown:  make(chan struct{}),
		senderDown:  make(chan struct{}),
		sendAckCh:   make(chan *messageAck),
		sendTextCh:  make(chan *sendTextReq),
		sendImageCh: make(chan *sendImageReq),
	}
	// Wrap the connection into the NaCl crypto stream and login
	c.conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := c.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.login(); err != nil {
		conn.Close()
		return nil, err
	}
	c.conn.SetDeadline(time.Time{}) // Login succeeded, disable timeouts

	// Keep retrieving messages until the connection dies
	go c.reader()
	go c.sender()

	return c, nil
}

// Close tears down the network connection.
func (c *Connection) Close() error {
	return c.conn.Close()
}

// handshake runs the Threema cross crypto authentication. It is used to set up
// the secure communication channel between the Threema server and a local random
// identity. The login authentication is done in a later step.
//
// The result of the handshake will be a negotiated client/server nonce cookie
// and a negotiated client/server short term key to be used for the connection.
func (c *Connection) handshake() error {
	// The session uses a temporary key. We could reuse it a few times, but screw
	// statefulness, just generate a new one when connecting.
	sessPubKey, sessSecKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// Send over the client hello
	clientCookie := make([]byte, cookieLength)
	if _, err := io.ReadFull(rand.Reader, clientCookie); err != nil {
		return err
	}
	if _, err := c.conn.Write((*sessPubKey)[:]); err != nil {
		return err
	}
	if _, err := c.conn.Write(clientCookie); err != nil {
		return err
	}
	// Read the server hello
	serverCookie := make([]byte, cookieLength)
	if _, err := io.ReadFull(c.conn, serverCookie); err != nil {
		return err
	}
	serverHelloEnc := make([]byte, publicLength+cookieLength+box.Overhead)
	if _, err := io.ReadFull(c.conn, serverHelloEnc); err != nil {
		return err
	}
	// Decrypt the server hello
	serverNonce := newNonce(serverCookie)

	serverHelloDec, ok := box.Open(nil, serverHelloEnc, serverNonce.inc(), chatServerKey, sessSecKey)
	if !ok {
		return errors.New("failed to decrypt server hello")
	}
	// Extract server temporary key and verify the echoed client cookie
	var servPubKey [publicLength]byte
	copy(servPubKey[:], serverHelloDec)

	if !bytes.Equal(clientCookie, serverHelloDec[publicLength:]) {
		return fmt.Errorf("echoed client cookie doesn't match local: have %x, want %x", clientCookie, serverHelloDec[publicLength:])
	}
	// Connection seems to be ok crypto wise, init and return for login
	c.clientNonce = newNonce(clientCookie)
	c.serverNonce = serverNonce
	c.clientKey = sessSecKey
	c.serverKey = &servPubKey

	return nil
}

// login authenticates the local user into the Threema network.
func (c *Connection) login() error {
	// Create a digital signature to authorize the short term session public key
	// with our long term identity secret key.
	var clientPubKey [publicLength]byte
	curve25519.ScalarBaseMult(&clientPubKey, c.clientKey)

	var authNonce [nonceLength]byte
	if _, err := io.ReadFull(rand.Reader, authNonce[:]); err != nil {
		return err
	}
	authVouch := box.Seal(nil, clientPubKey[:], &authNonce, chatServerKey, c.id.secretKey)

	// Create a list of protocol metadata to feed into the server
	var metadata []byte

	metadata = append(metadata, append([]byte{0x00, byte(len(chatClientMetadata)), 0x00}, []byte(chatClientMetadata)...)...) // Client info
	metadata = append(metadata, append([]byte{0x02, 0x01, 0x00}, 0x01)...)                                                   // Payload version

	// Assemble the login packet to authenticate the user
	var login []byte

	login = append(login, []byte(c.id.identity)...)                                                                    // Registered user ID
	login = append(login, append([]byte("threema-clever-extension-field"), byte(len(metadata)+box.Overhead), 0x00)...) // Protocol magic
	login = append(login, c.serverNonce[:cookieLength]...)                                                             // Confirm the server cookie
	login = append(login, authNonce[:]...)                                                                             // Send in the auth nonce
	login = append(login, authVouch...)                                                                                // Confirm the short term key

	loginEnc := box.Seal(nil, login, c.clientNonce.inc(), c.serverKey, c.clientKey)
	if _, err := c.conn.Write(loginEnc); err != nil {
		return err
	}
	metadataEnc := box.Seal(nil, metadata, c.clientNonce.inc(), c.serverKey, c.clientKey)
	if _, err := c.conn.Write(metadataEnc); err != nil {
		return err
	}
	loginAckEnc := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, loginAckEnc); err != nil {
		return err
	}
	_, ok := box.Open(nil, loginAckEnc, c.serverNonce.inc(), c.serverKey, c.clientKey)
	if !ok {
		return errors.New("failed to decrypt server login ack")
	}
	return nil
}

// nonce is a helper to initialize a NaCl nonce from a session cookie and to add
// a few methods for incrementing it and returning it in NaCl specific format.
type nonce [nonceLength]byte

// newNonce creates a new nonce out of a session cookie.
func newNonce(cookie []byte) *nonce {
	var n nonce
	copy(n[:], cookie)
	return &n
}

// inc bumps the nonce by one and returns it in a suitable format for nacl.
func (n *nonce) inc() *[nonceLength]byte {
	counter := binary.LittleEndian.Uint64(n[cookieLength:])
	binary.LittleEndian.PutUint64(n[cookieLength:], counter+1)

	cast := [nonceLength]byte(*n)
	return &cast
}
