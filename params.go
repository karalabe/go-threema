// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

var (
	// These are the chat server details of Threema
	chatServerPrefixV4 = "g-"            // Prefix for the IPv4 chat server
	chatServerGroup    = "33"            // Server group (retrievable from REST)
	chatServerSuffix   = ".0.threema.ch" // Suffix for all servers
	chatServerPort     = 5222            // Listener port

	chatServerKey    = &[publicLength]byte{0x45, 0x0b, 0x97, 0x57, 0x35, 0x27, 0x9f, 0xde, 0xcb, 0x33, 0x13, 0x64, 0x8f, 0x5f, 0xc6, 0xee, 0x9f, 0xf4, 0x36, 0x0e, 0xa9, 0x2a, 0x8c, 0x17, 0x51, 0xc6, 0x61, 0xe4, 0xc0, 0xd8, 0xc9, 0x09}
	chatServerKeyAlt = &[publicLength]byte{0xda, 0x7c, 0x73, 0x79, 0x8f, 0x97, 0xd5, 0x87, 0xc3, 0xa2, 0x5e, 0xbe, 0x0a, 0x91, 0x41, 0x7f, 0x76, 0xdb, 0xcc, 0xcd, 0xda, 0x29, 0x30, 0xe6, 0xa9, 0x09, 0x0a, 0xf6, 0x2e, 0xba, 0x6f, 0x15}

	// chatClientMetadata is the stats we report to the Threema chat server in the
	// shape of "Version;PlatformCode;Language/Country;SystemModel;SystemVersion"
	// - Version:       short string in the format major.minor (e.g. "1.0")
	// - PlatformCode:  single letter (A = Android, I = iPhone, J = Generic Java)
	// - Language:      ISO 639-1 (e.g. "de", "en")
	// - Country:       ISO 3166-1 (e.g. "CH", "DE", "US")
	// - SystemModel:   phone model
	// - SystemVersion: Android version string
	chatClientMetadata = "4.64;A;en;CH;Pixel 6;12"

	// These are the blob server details of Threema
	blobServerUpload   = "https://blobp-upload.threema.ch/upload"
	blobServerDownload = "https://blobp-{prefix}.threema.ch/"

	// blobClientMetadata is the client id we report to the Threema blob server
	// in the shape of "Threema/Version || PlatformCode"
	blobClientMetadata = "Threema/4.64A"
)
