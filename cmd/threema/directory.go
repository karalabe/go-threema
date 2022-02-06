// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// lookupPubkey retrieves the public key associated with a Threema user based on
// their 8 letter Threema ID.
func lookupPubkey(id string) (string, error) {
	// Make an HTTP client that ignores the certificates. The worse that could
	// happen is that we encrypt a message with a wrong key and the recipient
	// won't be able to parse it.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// Load the Threema user directory
	res, err := client.Get("https://api.threema.ch/identity/" + id)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.New(res.Status)
	}
	// Try to parse out the public key
	var response struct {
		Identity string `json:"identity"`
		Pubkey   string `json:"publicKey"`
	}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return "", err
	}
	if response.Identity != id {
		return "", fmt.Errorf("response id mismatch: have %s, want %s", response.Identity, id)
	}
	return response.Pubkey, nil
}
