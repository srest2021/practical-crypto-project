// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	age "github.com/srest2021/practical-crypto-project"
	"github.com/srest2021/practical-crypto-project/agessh"
	"github.com/srest2021/practical-crypto-project/armor"
	"github.com/srest2021/practical-crypto-project/plugin"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

type gitHubRecipientError struct {
	username string
}

func (gitHubRecipientError) Error() string {
	return `"github:" recipients were removed from the design`
}

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1") && strings.Count(arg, "1") > 1:
		return plugin.NewRecipient(arg, pluginTerminalUI)
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return agessh.ParseRecipient(arg)
	case strings.HasPrefix(arg, "github:"):
		name := strings.TrimPrefix(arg, "github:")
		return nil, gitHubRecipientError{name}
	}

	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

func parseHybridRecipient(line1 string, line2 string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(line1, "agex1") && strings.HasPrefix(line2, "agek1"):
		x25519_r, err := age.ParseX25519Recipient(line1)
		if err != nil {
			return nil, fmt.Errorf("error parsing X25519 recipient: %v", err)
		}

		kyber_r, err := age.ParseKyberRecipient(line2)
		if err != nil {
			return nil, fmt.Errorf("error parsing Kyber recipient: %v", err)
		}

		r := age.CreateHybridRecipient(x25519_r, kyber_r)
		return r, nil

	case strings.HasPrefix(line1, "agek1") && strings.HasPrefix(line2, "agex1"):
		kyber_r, err := age.ParseKyberRecipient(line1)
		if err != nil {
			return nil, fmt.Errorf("error parsing Kyber recipient: %v", err)
		}

		x25519_r, err := age.ParseX25519Recipient(line2)
		if err != nil {
			return nil, fmt.Errorf("error parsing X25519 recipient: %v", err)
		}

		r := age.CreateHybridRecipient(x25519_r, kyber_r)
		return r, nil
	}
	return nil, fmt.Errorf("error parsing hybrid recipient")
}

func parseRecipientsFile(name string) ([]age.Recipient, error) {
	var f *os.File
	if name == "-" {
		if stdinInUse {
			return nil, fmt.Errorf("standard input is used for multiple purposes")
		}
		stdinInUse = true
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open recipient file: %v", err)
		}
		defer f.Close()
	}

	const recipientFileSizeLimit = 16 << 20 // 16 MiB
	const lineLengthLimit = 8 << 10         // 8 KiB, same as sshd(8)
	var recs []age.Recipient
	scanner := bufio.NewScanner(io.LimitReader(f, recipientFileSizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line1 := scanner.Text()
		if strings.HasPrefix(line1, "#") || line1 == "" {
			continue
		}
		if len(line1) > lineLengthLimit {
			return nil, fmt.Errorf("%q: line %d is too long", name, n)
		}

		for scanner.Scan() {
			n++
			line2 := scanner.Text()
			if strings.HasPrefix(line2, "#") || line2 == "" {
				continue
			}
			if len(line2) > lineLengthLimit {
				return nil, fmt.Errorf("%q: line %d is too long", name, n)
			}

			r, err := parseHybridRecipient(line1, line2)
			if err != nil {
				// Hide the error since it might unintentionally leak the contents
				// of confidential files.
				return nil, fmt.Errorf("%q: malformed recipient at lines %d-%d", name, n-1, n)
			}
			recs = append(recs, r)
			break
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("%q: failed to read recipients file: %v", name, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%q: failed to read recipients file: %v", name, err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%q: no recipients found", name)
	}
	return recs, nil
}

func sshKeyType(s string) (string, bool) {
	// TODO: also ignore options? And maybe support multiple spaces and tabs as
	// field separators like OpenSSH?
	fields := strings.Split(s, " ")
	if len(fields) < 2 {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	k := cryptobyte.String(key)
	var typeLen uint32
	var typeBytes []byte
	if !k.ReadUint32(&typeLen) || !k.ReadBytes(&typeBytes, int(typeLen)) {
		return "", false
	}
	if t := fields[0]; t == string(typeBytes) {
		return t, true
	}
	return "", false
}

// parseIdentitiesFile parses a file that contains age or SSH keys. It returns
// one or more of *age.X25519Identity, *agessh.RSAIdentity, *agessh.Ed25519Identity,
// *agessh.EncryptedSSHIdentity, or *EncryptedIdentity.
func parseIdentitiesFile(name string) ([]age.Identity, error) {
	var f *os.File
	if name == "-" {
		if stdinInUse {
			return nil, fmt.Errorf("standard input is used for multiple purposes")
		}
		stdinInUse = true
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
		defer f.Close()
	}

	b := bufio.NewReader(f)
	p, _ := b.Peek(14) // length of "age-encryption" and "-----BEGIN AGE"
	peeked := string(p)

	switch {
	// An age encrypted file, plain or armored.
	case peeked == "age-encryption" || peeked == "-----BEGIN AGE":
		var r io.Reader = b
		if peeked == "-----BEGIN AGE" {
			r = armor.NewReader(r)
		}
		const privateKeySizeLimit = 1 << 24 // 16 MiB
		contents, err := io.ReadAll(io.LimitReader(r, privateKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		if len(contents) == privateKeySizeLimit {
			return nil, fmt.Errorf("failed to read %q: file too long", name)
		}
		return []age.Identity{&EncryptedIdentity{
			Contents: contents,
			Passphrase: func() (string, error) {
				pass, err := readSecret(fmt.Sprintf("Enter passphrase for identity file %q:", name))
				if err != nil {
					return "", fmt.Errorf("could not read passphrase: %v", err)
				}
				return string(pass), nil
			},
			NoMatchWarning: func() {
				warningf("encrypted identity file %q didn't match file's recipients", name)
			},
		}}, nil

	// Another PEM file, possibly an SSH private key.
	case strings.HasPrefix(peeked, "-----BEGIN"):
		const privateKeySizeLimit = 1 << 14 // 16 KiB
		contents, err := io.ReadAll(io.LimitReader(b, privateKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		if len(contents) == privateKeySizeLimit {
			return nil, fmt.Errorf("failed to read %q: file too long", name)
		}
		return parseSSHIdentity(name, contents)

	// An unencrypted age identity file.
	default:
		ids, err := parseIdentities(b)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		return ids, nil
	}
}

func parseIdentity(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, pluginTerminalUI)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	default:
		return nil, fmt.Errorf("unknown identity type")
	}
}

func parseHybridIdentity(line1 string, line2 string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(line1, "AGE-X-SECRET-KEY-1") && strings.HasPrefix(line2, "AGE-K-SECRET-KEY-1"):
		x25519_i, err := age.ParseX25519Identity(line1)
		if err != nil {
			return nil, fmt.Errorf("error parsing X25519 identity: %v", err)
		}

		kyber_i, err := age.ParseKyberIdentity(line2)
		if err != nil {
			return nil, fmt.Errorf("error parsing Kyber identity: %v", err)
		}

		i := age.CreateHybridIdentity(x25519_i, kyber_i)
		return i, nil

	case strings.HasPrefix(line1, "AGE-K-SECRET-KEY-1") && strings.HasPrefix(line2, "AGE-X-SECRET-KEY-1"):
		kyber_i, err := age.ParseKyberIdentity(line1)
		if err != nil {
			return nil, fmt.Errorf("error parsing Kyber identity: %v", err)
		}

		x25519_i, err := age.ParseX25519Identity(line2)
		if err != nil {
			return nil, fmt.Errorf("error parsing X25519 identity: %v", err)
		}

		i := age.CreateHybridIdentity(x25519_i, kyber_i)
		return i, nil
	}
	return nil, fmt.Errorf("error parsing hybrid identity")
}

// parseIdentities is like age.ParseIdentities, but supports plugin identities.
func parseIdentities(f io.Reader) ([]age.Identity, error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []age.Identity
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		i, err := parseIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)

	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read secret keys file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found")
	}
	return ids, nil
}

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			pass, err := readSecret(fmt.Sprintf("Enter passphrase for %q:", name))
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
			}
			return pass, nil
		}
		i, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
		if err != nil {
			return nil, err
		}
		return []age.Identity{i}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	return []age.Identity{id}, nil
}

func readPubFile(name string) (ssh.PublicKey, error) {
	if name == "-" {
		return nil, fmt.Errorf(`failed to obtain public key for "-" SSH key

Use a file for which the corresponding ".pub" file exists, or convert the private key to a modern format with "ssh-keygen -p -m RFC4716"`)
	}
	f, err := os.Open(name + ".pub")
	if err != nil {
		return nil, fmt.Errorf(`failed to obtain public key for %q SSH key: %v

Ensure %q exists, or convert the private key %q to a modern format with "ssh-keygen -p -m RFC4716"`, name, err, name+".pub", name)
	}
	defer f.Close()
	contents, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name+".pub", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
	}
	return pubKey, nil
}
