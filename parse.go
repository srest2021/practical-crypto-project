// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"
)

// ParseIdentities parses a file with one or more private key encodings, one per
// line. Empty lines and lines starting with "#" are ignored.
//
// This is the same syntax as the private key files accepted by the CLI, except
// the CLI also accepts SSH private keys, which are not recommended for the
// average application.
//
// Currently, all returned values are of type *X25519Identity, but different
// types might be returned in the future.
func ParseIdentities(f io.Reader) ([]Identity, error) {
	log.Printf("got here")
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []Identity
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line1 := scanner.Text()
		if strings.HasPrefix(line1, "#") || line1 == "" {
			continue
		}
		log.Printf("scanned line1: %s", line1)

		for scanner.Scan() {
			n++
			line2 := scanner.Text()
			if strings.HasPrefix(line2, "#") || line2 == "" {
				continue
			}
			log.Printf("scanned line2: %s", line2)

			var x25519_i *X25519Identity
			var kyber_i *KyberIdentity

			if strings.HasPrefix(line1, "AGE-X-SECRET-KEY-") && strings.HasPrefix(line2, "AGE-K-SECRET-KEY-") {
				x25519_i, _ = ParseX25519Identity(line1)
				kyber_i, _ = ParseKyberIdentity(line2)
			} else if strings.HasPrefix(line1, "AGE-K-SECRET-KEY-") && strings.HasPrefix(line2, "AGE-X-SECRET-KEY-") {
				x25519_i, _ = ParseX25519Identity(line2)
				kyber_i, _ = ParseKyberIdentity(line1)
			} else {
				return nil, fmt.Errorf("error at line %d: must have a X25519-Kyber768 identity pair", n)
			}

			i := CreateHybridIdentity(x25519_i, kyber_i)
			ids = append(ids, i)
			break
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read secret keys file: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read secret keys file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found")
	}
	return ids, nil
}

// ParseRecipients parses a file with one or more public key encodings, one per
// line. Empty lines and lines starting with "#" are ignored.
//
// This is the same syntax as the recipients files accepted by the CLI, except
// the CLI also accepts SSH recipients, which are not recommended for the
// average application.
//
// Currently, all returned values are of type *X25519Recipient, but different
// types might be returned in the future.
func ParseRecipients(f io.Reader) ([]Recipient, error) {
	const recipientFileSizeLimit = 1 << 24 // 16 MiB
	var recs []Recipient
	scanner := bufio.NewScanner(io.LimitReader(f, recipientFileSizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line1 := scanner.Text()
		if strings.HasPrefix(line1, "#") || line1 == "" {
			continue
		}

		for scanner.Scan() {
			n++
			line2 := scanner.Text()
			if strings.HasPrefix(line2, "#") || line1 == "" {
				continue
			}

			var x25519_r *X25519Recipient
			var kyber_r *KyberRecipient

			if strings.HasPrefix(line1, "agex") && strings.HasPrefix(line2, "agek") {
				x25519_r, _ = ParseX25519Recipient(line1)
				kyber_r, _ = ParseKyberRecipient(line2)
			} else if strings.HasPrefix(line1, "agek") && strings.HasPrefix(line2, "agex") {
				x25519_r, _ = ParseX25519Recipient(line2)
				kyber_r, _ = ParseKyberRecipient(line1)
			} else {
				return nil, fmt.Errorf("error at line %d: must have a X25519-Kyber768 recipient pair", n)
			}

			r := CreateHybridRecipient(x25519_r, kyber_r)
			recs = append(recs, r)
			break
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read recipients file: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read recipients file: %v", err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no recipients found")
	}
	return recs, nil
}
