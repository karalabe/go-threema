// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

const (
	// blobidLength is the number of bytes in a blob ID returned for uploads.
	blobidLength = 16
)

// uploadBlob uploads a blob to the Threema servers and returns the assigned ID.
func uploadBlob(blob []byte) ([]byte, error) {
	// Preprocess the image into a multipart file blob
	var buffer bytes.Buffer

	w := multipart.NewWriter(&buffer)
	part, err := w.CreateFormFile("blob", "blob.bin")
	if err != nil {
		return nil, err
	}
	io.Copy(part, bytes.NewReader(blob))

	w.Close()

	// Execute the upload request to the blob server
	req, err := http.NewRequest("POST", blobServerUpload, &buffer)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", blobClientMetadata)
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}
	// Retrieve the blob ID (hex) from the server to forward to the recipient
	id := make([]byte, blobidLength)

	if _, err := io.ReadFull(hex.NewDecoder(res.Body), id); err != nil {
		return nil, err
	}
	return id, nil
}

// downloadBlob downloads a blob from the Threema servers.
func downloadBlob(id string) ([]byte, error) {
	url := strings.ReplaceAll(blobServerDownload, "{prefix}", id[:2]) + id

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", blobClientMetadata)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}
