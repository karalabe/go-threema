// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"errors"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"time"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/vp8"
	_ "golang.org/x/image/vp8l"
	_ "golang.org/x/image/webp"
)

// Handler defines the various events that the user's code needs to handle (or
// ignore if so they chose).
type Handler struct {
	// Spam is called when we receive a message from a Threema user not on the
	// local contact list. The expectation is that no unexpected messages should
	// be consumed, so we notify the handler, but don't act further on it.
	Spam func(from string, nick string, when time.Time)

	// Message is called when the account receives a remote message.
	Message func(from string, nick string, when time.Time, msg string)

	// Image is called when the account receives a remote image transfer.
	Image func(from string, nick string, when time.Time, image image.Image, thumb image.Image, caption string)

	// Alert is called when the Threema server sends a warning to the user.
	Alert func(reason string)

	// Error is called when the Threema server sends us an error, specifying if
	// it is allowed to reconnect or not.
	Error func(reason string, reconnect bool)

	// Closed is called when the connection to the Threema server terminates.
	Closed func()
}

// SendText sends a text message to the given recipient.
func (c *Connection) SendText(to string, text string) error {
	errc := make(chan error)
	select {
	case c.sendTextCh <- &sendTextReq{to: to, text: text, sent: errc}:
		return <-errc
	case <-c.senderDown:
		return errors.New("connection closed")
	}
}

// sendTextReq is an internal envelope to bundle up the user request and send it
// over to the connection for serialization, encryption and transfer.
type sendTextReq struct {
	to   string
	text string
	sent chan error
}

// SendImage sends an image to the given recipient.
func (c *Connection) SendImage(to string, blob []byte, caption string) error {
	// Generate a small jpeg thumbnail to download first
	src, _, err := image.Decode(bytes.NewBuffer(blob))
	if err != nil {
		return err
	}
	dst := new(bytes.Buffer)
	if err := jpeg.Encode(dst, src, &jpeg.Options{Quality: 25}); err != nil {
		return err
	}
	errc := make(chan error)
	select {
	case c.sendImageCh <- &sendImageReq{
		to:      to,
		image:   blob,
		width:   src.Bounds().Dx(),
		height:  src.Bounds().Dy(),
		thumb:   dst.Bytes(),
		caption: caption,
		sent:    errc,
	}:
		return <-errc
	case <-c.senderDown:
		return errors.New("connection closed")
	}
}

// sendImageReq is an internal envelope to bundle up the user request and send it
// over to the connection for serialization, encryption and transfer.
type sendImageReq struct {
	to      string
	image   []byte
	width   int
	height  int
	thumb   []byte
	caption string
	sent    chan error
}
