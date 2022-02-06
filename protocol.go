// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	// Control messages sent from the client to the server
	payloadEchoRequest        = 0x00
	payloadOutgoungMessage    = 0x01
	payloadIncomingMessageAck = 0x82

	// PAYLOAD_PUSH_NOTIFICATION_TOKEN      = 0x20
	// PAYLOAD_PUSH_ALLOWED_IDENTITIES      = 0x21
	// PAYLOAD_VOIP_PUSH_NOTIFICATION_TOKEN = 0x24

	// Control message send from the server to the client
	payloadIncomingMessage    = 0x02
	payloadEchoReply          = 0x80
	payloadOutgoingMessageAck = 0x81
	payloadQueueSendComplete  = 0xd0
	payloadError              = 0xe0
	payloadAlert              = 0xe1
)

const (
	messageText                = 0x01
	messageImage               = 0x02
	messageLocation            = 0x10
	messageVideo               = 0x13
	messageAudio               = 0x14
	messageBallotCreate        = 0x15
	messageBallotVote          = 0x16
	messageFile                = 0x17
	messageContactSetPhoto     = 0x18
	messageContactDeletePhoto  = 0x19
	messageContactRequestPhoto = 0x1a
	messageGroupText           = 0x41
	messageGroupLocation       = 0x42
	messageGroupImage          = 0x43
	messageGroupVideo          = 0x44
	messageGroupAudio          = 0x45
	messageGroupFile           = 0x46
	messageGroupCreate         = 0x4a
	messageGroupRename         = 0x4b
	messageGroupLeave          = 0x4c
	messageGroupJoinRequest    = 0x4d
	messageGroupJoinResponse   = 0x4e
	messageGroupSetPhoto       = 0x50
	messageGroupRequestSync    = 0x51
	messageGroupBallotCreate   = 0x52
	messageGroupBallotVote     = 0x53
	messageGroupDeletePhoto    = 0x54
	messageVoipCallOffer       = 0x60
	messageVoipCallAnswer      = 0x61
	messageVoipIceCandidates   = 0x62
	messageVoipCallHangup      = 0x63
	messageVoipCallRinging     = 0x64
	messageDeliveryReceipt     = 0x80
	messageTypingIndicator     = 0x90
	messageAuthToken           = 0xff
)

const (
	// heartbeat is the interval at which to send an echo message to keep the
	// connection to the server alive.
	heartbeat = 3 * time.Minute
)

// reader is an infinite loop that keeps pulling and delivering messages until
// the connection dies.
func (c *Connection) reader() {
	// If the reader terminates, signal that the connection was severed
	defer func() {
		if c.handler.Closed != nil {
			c.handler.Closed()
		}
	}()
	defer close(c.readerDown)

	for {
		// Read the next 2 bytes as the message length marker
		len := make([]byte, 2)
		if _, err := io.ReadFull(c.conn, len); err != nil {
			return
		}
		// Read the encrypted NaCl box and decrypt it
		enc := make([]byte, binary.LittleEndian.Uint16(len))
		if _, err := io.ReadFull(c.conn, enc); err != nil {
			return
		}
		dec, ok := box.Open(nil, enc, c.serverNonce.inc(), c.serverKey, c.clientKey)
		if !ok {
			panic("failed to decrypt server message") // Big boo boo
		}
		// Extract the payload type and it's content
		var (
			kind    = dec[0]  // First 4 bytes are little endian encoded 1 byte type (lol)
			content = dec[4:] // Content starts after the 4 byte encoded 1 byte type
		)
		switch kind {
		case payloadIncomingMessage:
			// Yay, something sent us something, unpack it
			from := string(content[:identityLength])
			content = content[identityLength:]

			// to := string(content[:identityLength])
			content = content[identityLength:]

			id := binary.LittleEndian.Uint64(content)
			content = content[8:]

			when := time.Unix(int64(binary.LittleEndian.Uint32(content)), 0)
			content = content[4:]

			content = content[2:] // reserved

			metalen := binary.LittleEndian.Uint16(content)
			content = content[2:]

			nick := strings.Trim(string(content[:32]), string([]byte{0x00}))
			content = content[32:]

			// meta := content[:metalen]
			content = content[metalen:]

			var nonce [nonceLength]byte
			copy(nonce[:], content)
			content = content[nonceLength:]

			// If we have the required contact, decode the message. Otherwise
			// notify the handler of the weird contact. Don't automatically pull
			// from the Threema identity server, we're simple and dumb.
			if peerkey, ok := c.id.contacts[from]; !ok {
				if c.handler.Spam == nil {
					log.Printf("No handler for spam messages")
				} else {
					c.handler.Spam(from, nick, when)
				}
			} else {
				message, ok := box.Open(nil, content, &nonce, peerkey, c.id.secretKey)
				if !ok {
					if c.handler.Spam == nil {
						log.Printf("No handler for spam messages")
					} else {
						c.handler.Spam(from, nick, when)
					}
				} else {
					c.handleMessage(from, nick, when, message)
				}
			}
			// Either way, ack the message to avoid double delivers
			select {
			case c.sendAckCh <- &messageAck{sender: from, id: id}:
			case <-c.senderDown:
				c.conn.Close()
				return
			}

		case payloadEchoReply:
			// We'll just assume Threema is healthy, no need to verify heartbeat pongs

		case payloadOutgoingMessageAck:
			// We'll just assume Threema is healthy, no need to track send message for now

		case payloadQueueSendComplete:
			// All queued up message received... nothing to meaningfully do

		case payloadError:
			// Server sent us an error message, tell the user there's something wrong
			if c.handler.Error == nil {
				log.Printf("No handler for protocol errors")
				continue
			}
			c.handler.Error(string(content[1:]), content[0] != 0x00)

		case payloadAlert:
			// Server sent us an alert, bubble it up to the user
			if c.handler.Alert == nil {
				log.Printf("No handler for protocol alerts")
				continue
			}
			c.handler.Alert(string(content))

		default:
			log.Printf("Unknown payload type from Threema server: %d", kind)
		}
	}
}

// handleMessage is responsible for unpacking an application layer message and
// delivering it to the user handler.
func (c *Connection) handleMessage(from string, nick string, when time.Time, content []byte) {
	switch content[0] {
	case messageText:
		// We've received a message, deliver it upstream
		padding := int(content[len(content)-1])
		if c.handler.Message == nil {
			log.Printf("No handler for text messages")
			return
		}
		c.handler.Message(from, nick, when, string(content[1:len(content)-padding]))

	case messageDeliveryReceipt:
		// Remote user acked the delivery of our message, we don't care for now

	default:
		log.Printf("Unknown message type from Threema user: %d", content[0])
	}
}

// messageAck is a Threema wire ack for receiving a remote message.
type messageAck struct {
	sender string
	id     uint64
}

// sender is an loop that keeps sending messages until the connection dies.
func (c *Connection) sender() {
	// If the sender terminates, signal that no more messages are accepted
	defer close(c.senderDown)

	// Send a heartbeat every now and again
	pinger := time.NewTimer(1) // Trigger an echo instantly
	defer pinger.Stop()

	for {
		// Retrieve the next wire message to send and serialize it
		var (
			message []byte
			unblock chan error
		)
		select {
		case <-c.readerDown:
			// The remote connection was interrupted, terminate even if we're idle
			return

		case <-pinger.C:
			// A lot of time passed since the last ping, make sure the connection
			// and routing tables stay alive.
			message = append(message, []byte{payloadEchoRequest, 0x00, 0x00, 0x00}...)
			message = append(message, serializeUint32(uint32(0))...) // we're not tracking the echo, same seqnum is fine

			// Restart the ping timer
			pinger.Reset(heartbeat)

		case ack := <-c.sendAckCh:
			// We've received a message, ack it to not get it again
			message = append(message, []byte{payloadIncomingMessageAck, 0x00, 0x00, 0x00}...)
			message = append(message, []byte(ack.sender)...)
			message = append(message, make([]byte, 8)...)
			binary.LittleEndian.PutUint64(message[len(message)-8:], ack.id)

		case msg := <-c.sendTextCh:
			// We're sending a text message, serialize it for the recipient
			nonce, payload, err := c.serializeTextMessage(msg.to, msg.text)
			if err != nil {
				msg.sent <- err
				continue
			}
			id := make([]byte, 8)
			if _, err := io.ReadFull(rand.Reader, id); err != nil {
				msg.sent <- err
				continue
			}
			unblock = msg.sent

			// Bundle up all the metadata before the actual content
			message = append(message, []byte{payloadOutgoungMessage, 0x00, 0x00, 0x00}...)
			message = append(message, []byte(c.id.identity)...)
			message = append(message, []byte(msg.to)...)
			message = append(message, id...)
			message = append(message, serializeUint32(uint32(time.Now().Unix()))...)
			message = append(message, []byte{0x01}...)       // push the message
			message = append(message, []byte{0x00}...)       // reserved
			message = append(message, []byte{0x00, 0x00}...) // metalen
			message = append(message, make([]byte, 32)...)   // nick
			message = append(message, nonce...)
			message = append(message, payload...)

		}
		// Message binary constructed, encrypt and deliver it to Threema
		payload := box.Seal(nil, message, c.clientNonce.inc(), c.serverKey, c.clientKey)

		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(len(payload)))
		if _, err := c.conn.Write(length); err != nil {
			if unblock != nil {
				unblock <- err
			}
			c.conn.Close()
			return
		}
		if _, err := c.conn.Write(payload); err != nil {
			if unblock != nil {
				unblock <- err
			}
			c.conn.Close()
			return
		}
		if unblock != nil {
			unblock <- nil
		}
	}
}

// serializeTextMessage converts a recipient and a text message into an encrypted
// Threema message.
func (c *Connection) serializeTextMessage(to string, text string) ([]byte, []byte, error) {
	// Create the tagged and padded plaintext message
	var blob []byte

	blob = append(blob, byte(messageText))
	blob = append(blob, []byte(text)...)

	padding := 256 - (len(blob) % 256) - 1
	blob = append(blob, bytes.Repeat([]byte{0x00}, padding)...)
	blob = append(blob, byte(padding))

	// Encrypt it with the user's public key
	pubkey, ok := c.id.contacts[to]
	if !ok {
		return nil, nil, fmt.Errorf("recipient not a known contact: %s", to)
	}
	var nonce [nonceLength]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, err
	}
	return nonce[:], box.Seal(nil, blob, &nonce, pubkey, c.id.secretKey), nil
}

// serializeUint32 is a small helper to avoid the annoying 3 liner API.
func serializeUint32(n uint32) []byte {
	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, n)
	return blob
}
