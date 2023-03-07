// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
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
	messageText                = byte(0x01) // Simple text messages between users
	messageImage               = byte(0x02) // Legacy? Not processed by the Android client
	messageLocation            = byte(0x10)
	messageVideo               = byte(0x13)
	messageAudio               = byte(0x14)
	messageBallotCreate        = byte(0x15)
	messageBallotVote          = byte(0x16)
	messageFile                = byte(0x17)
	messageContactSetPhoto     = byte(0x18)
	messageContactDeletePhoto  = byte(0x19)
	messageContactRequestPhoto = byte(0x1a)
	messageGroupText           = byte(0x41)
	messageGroupLocation       = byte(0x42)
	messageGroupImage          = byte(0x43)
	messageGroupVideo          = byte(0x44)
	messageGroupAudio          = byte(0x45)
	messageGroupFile           = byte(0x46)
	messageGroupCreate         = byte(0x4a)
	messageGroupRename         = byte(0x4b)
	messageGroupLeave          = byte(0x4c)
	messageGroupJoinRequest    = byte(0x4d)
	messageGroupJoinResponse   = byte(0x4e)
	messageGroupSetPhoto       = byte(0x50)
	messageGroupRequestSync    = byte(0x51)
	messageGroupBallotCreate   = byte(0x52)
	messageGroupBallotVote     = byte(0x53)
	messageGroupDeletePhoto    = byte(0x54)
	messageVoipCallOffer       = byte(0x60)
	messageVoipCallAnswer      = byte(0x61)
	messageVoipIceCandidates   = byte(0x62)
	messageVoipCallHangup      = byte(0x63)
	messageVoipCallRinging     = byte(0x64)
	messageDeliveryReceipt     = byte(0x80)
	messageTypingIndicator     = byte(0x90)
	messageAuthToken           = byte(0xff)
)

var (
	fileMessageBlobNonce  = [nonceLength]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	fileMessageThumbNonce = [nonceLength]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
)

const (
	// heartbeat is the interval at which to send an echo message to keep the
	// connection to the server alive.
	heartbeat = 3 * time.Minute
)

// fileMessage is the payload of a file announcement. To make things interesting,
// it is JSON opposed to all the other binary messages.
type fileMessage struct {
	BlobID         string      `json:"b"`
	ThumbID        string      `json:"t"`
	SymKey         string      `json:"k"`
	BlobMime       string      `json:"m"`
	ThumbMime      string      `json:"p"`
	Name           string      `json:"n"`
	Size           int         `json:"s"`
	RenderTypeDepr int         `json:"i"`
	RenderType     int         `json:"j"`
	Desc           string      `json:"d,omitempty"`
	CorrID         string      `json:"c,omitempty"`
	Metadata       interface{} `json:"x"`
}

// reader is an infinite loop that keeps pulling and delivering messages until
// the connection dies.
func (c *Connection) reader() {
	// If the reader terminates, signal that the connection was severed
	defer func() {
		if c.handler.Closed == nil {
			log.Printf("No handler for connection termination")
			return
		}
		c.handler.Closed()
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
					log.Printf("No handler for spam messages from %s", from)
				} else {
					c.handler.Spam(from, nick, when)
				}
			} else {
				message, ok := box.Open(nil, content, &nonce, peerkey, c.id.secretKey)
				if !ok {
					if c.handler.Spam == nil {
						log.Printf("No handler for unencodable messages")
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

	case messageFile:
		// We've received a file message, parse the content and retrieve the data
		padding := int(content[len(content)-1])
		content := content[1 : len(content)-padding]

		var metadata fileMessage
		if err := json.Unmarshal(content, &metadata); err != nil {
			log.Printf("Failed to unmarshal file message: %v", err)
			return
		}
		encblob, err := downloadBlob(metadata.BlobID)
		if err != nil {
			log.Printf("Failed to retrieve main blob: %v", err)
			return
		}
		var encthumb []byte
		if len(metadata.ThumbID) > 0 {
			encthumb, err = downloadBlob(metadata.ThumbID)
			if err != nil {
				log.Printf("Failed to retrieve thumbnail blob: %v", err)
				return
			}
		}
		// Decrypt the primary and thumbnail blobs and deliver them upstream
		var key [symmetricLength]byte
		if _, err := hex.Decode(key[:], []byte(metadata.SymKey)); err != nil {
			log.Printf("Failed to parse symmetric key: %v", err)
			return
		}
		decblob, ok := secretbox.Open(nil, encblob, &fileMessageBlobNonce, &key)
		if !ok {
			log.Printf("Failed to decrypt main blob")
			return
		}
		var decthumb []byte
		if len(encthumb) > 0 {
			decthumb, ok = secretbox.Open(nil, encthumb, &fileMessageThumbNonce, &key)
			if !ok {
				log.Printf("Failed to decrypt main blob")
				return
			}
		}
		if c.handler.Message == nil {
			log.Printf("No handler for text messages")
			return
		}
		// We're yoloing it, just try to decode and if an image, be happy
		img, _, err := image.Decode(bytes.NewReader(decblob))
		if err != nil {
			log.Printf("Only image files are supported")
			return
		}
		var thumb image.Image
		if len(decthumb) > 0 {
			thumb, _, err = image.Decode(bytes.NewReader(decthumb))
			if err != nil {
				log.Printf("Failed to decode thumbnail: %v", err)
				return
			}
		}
		if c.handler.Image == nil {
			log.Printf("No handler for image messages")
			return
		}
		c.handler.Image(from, nick, when, img, thumb, metadata.Desc)

	case messageDeliveryReceipt:
		// Remote user acked the delivery of our message, we don't care for now

	default:
		log.Printf("Unknown message type from Threema user: %d: %x", content[0], content)
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
			err     error
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
			if message, err = c.serializeEnvelope(messageText, msg.to, []byte(msg.text)); err != nil {
				msg.sent <- err
				continue
			}
			unblock = msg.sent

		case msg := <-c.sendImageCh:
			// We're sending an image message, serialize and upload it to the
			// Threema blob server first since those are transmitted out of protocol.
			var symkey [symmetricLength]byte
			if _, err := io.ReadFull(rand.Reader, symkey[:]); err != nil {
				msg.sent <- err
				continue
			}
			blob := secretbox.Seal(nil, msg.image, &fileMessageBlobNonce, &symkey)
			blobID, err := uploadBlob(blob)
			if err != nil {
				msg.sent <- err
				continue
			}
			blobMime := http.DetectContentType(msg.image)
			blobExts, err := mime.ExtensionsByType(blobMime)
			if err != nil || len(blobExts) == 0 {
				msg.sent <- fmt.Errorf("failed to guess image file extension: %v", err)
				continue
			}
			thumb := secretbox.Seal(nil, msg.thumb, &fileMessageThumbNonce, &symkey)
			thumbID, err := uploadBlob(thumb)
			if err != nil {
				msg.sent <- err
				continue
			}
			timestamp := time.Now().UTC().Format("20060102-150405.000")
			timestamp = strings.ReplaceAll(timestamp, ".", "")

			payload, err := json.Marshal(&fileMessage{
				BlobID:         hex.EncodeToString(blobID),
				ThumbID:        hex.EncodeToString(thumbID),
				SymKey:         hex.EncodeToString(symkey[:]),
				BlobMime:       blobMime,
				ThumbMime:      http.DetectContentType(msg.thumb),
				Name:           "go-threema-" + timestamp + blobExts[0],
				Size:           len(msg.image),
				RenderTypeDepr: 1,
				RenderType:     1,
				Desc:           msg.caption,
				CorrID:         "",
				Metadata:       map[string]int{"h": msg.height, "w": msg.width},
			})
			if err != nil {
				msg.sent <- err
				continue
			}
			if message, err = c.serializeEnvelope(messageFile, msg.to, payload); err != nil {
				msg.sent <- err
				continue
			}
			unblock = msg.sent
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

// serializeEnvelope takes an already serialized app message, encrypts it and wraps
// the result into a  wire envelope for the chat server.
func (c *Connection) serializeEnvelope(kind byte, to string, payload []byte) ([]byte, error) {
	// Encrypt the cleartext payload to the designated recipient
	var plaintext []byte

	plaintext = append(plaintext, kind)
	plaintext = append(plaintext, payload...)

	padding := 256 - (len(plaintext) % 256) - 1
	plaintext = append(plaintext, bytes.Repeat([]byte{0x00}, padding)...)
	plaintext = append(plaintext, byte(padding+1))

	pubkey, ok := c.id.contacts[to]
	if !ok {
		return nil, fmt.Errorf("recipient not a known contact: %s", to)
	}
	var nonce [nonceLength]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	ciphertext := box.Seal(nil, plaintext, &nonce, pubkey, c.id.secretKey)

	// Package up the encrypted message into a wire envelope and return for delivery
	id := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return nil, err
	}
	var envelope []byte

	envelope = append(envelope, []byte{payloadOutgoungMessage, 0x00, 0x00, 0x00}...)
	envelope = append(envelope, []byte(c.id.identity)...)
	envelope = append(envelope, []byte(to)...)
	envelope = append(envelope, id...)
	envelope = append(envelope, serializeUint32(uint32(time.Now().Unix()))...)
	envelope = append(envelope, []byte{0x01}...)       // push the message
	envelope = append(envelope, []byte{0x00}...)       // reserved
	envelope = append(envelope, []byte{0x00, 0x00}...) // metalen
	envelope = append(envelope, make([]byte, 32)...)   // nick
	envelope = append(envelope, nonce[:]...)
	envelope = append(envelope, ciphertext...)

	return envelope, nil
}

// serializeUint32 is a small helper to avoid the annoying 3 liner API.
func serializeUint32(n uint32) []byte {
	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, n)
	return blob
}
