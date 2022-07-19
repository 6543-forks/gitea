// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	"code.gitea.io/gitea/modules/log"

	"golang.org/x/crypto/ssh"
)

// GenKeyPair make a pair of public and private keys for SSH access.
// Public key is encoded in the format for inclusion in an OpenSSH authorized_keys file.
// Private Key generated is PEM encoded
func GenKeyPair(keyPath string) error {
	publicKey, privateKey, err := genKeyPair()
	if err != nil {
		return err
	}

	privKeyFile, err := os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err = privKeyFile.Close(); err != nil {
			log.Error("Close: %v", err)
		}
	}()
	if _, err := privKeyFile.Write(privateKey); err != nil {
		return err
	}

	pubKeyFile, err := os.OpenFile(keyPath+".pub", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err = pubKeyFile.Close(); err != nil {
			log.Error("Close: %v", err)
		}
	}()

	_, err = pubKeyFile.Write(publicKey)
	return err
}

func genKeyPair() (publicK, privateK []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// generate private key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privateK = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// generate public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	publicK = ssh.MarshalAuthorizedKey(pub)

	return privateK, publicK, nil
}
