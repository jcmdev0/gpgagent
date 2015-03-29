// Example program that will attempt to decrypt the first argument with
// gpg, acquiring the passphrase through gpg-agent.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/jcmdev0/gpgagent"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"os"
	"strings"
)

// Returns the first entity with a matching email.
func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}

	return nil
}

func promptFunction(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	conn, err := gpgagent.NewGpgAgentConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for _, key := range keys {
		cacheId := strings.ToUpper(hex.EncodeToString(key.PublicKey.Fingerprint[:]))
		// TODO: Add prompt, etc.
		request := gpgagent.PassphraseRequest{CacheKey: cacheId}
		passphrase, err := conn.GetPassphrase(&request)
		if err != nil {
			return nil, err
		}
		err = key.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return nil, err
		}
		return []byte(passphrase), nil
	}
	return nil, fmt.Errorf("Unable to find key")
}

func main() {
	flag.Parse()

	fileName := flag.Arg(0)
	if len(fileName) == 0 {
		fmt.Println("No file specified")
		os.Exit(1)
	}

	privringFile, err := os.Open(os.ExpandEnv("$HOME/.gnupg/secring.gpg"))
	if err != nil {
		panic(err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		panic(err)
	}

	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	md, err := openpgp.ReadMessage(file, privring, promptFunction, nil)
	if err != nil {
		panic(err)
	}

	data, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", string(data))
}
