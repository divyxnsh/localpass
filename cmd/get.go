/*
Copyright © 2020 Abhay Bhargav

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"

	"github.com/cockroachdb/pebble"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
)

// JSONValue => Struct to represent as a JSON object
type JSONValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// DecryptWithPrivateKey => Decrypts the blob of password data with the private key first
func DecryptWithPrivateKey(privPath string, wrappedData []byte) ([]byte, error) {
	//read private key
	priv, err := ioutil.ReadFile(privPath)
	if err != nil {
		return nil, err
	}

	privKey, err := ssh.ParseRawPrivateKey(priv)

	if err != nil {
		return nil, err
	}

	//get raw encrypted payload
	data, err := base64.StdEncoding.DecodeString(string(wrappedData))
	if err != nil {
		return nil, err
	}

	//parse the OpenSSH key as an RSA Private Key
	parsedKey := privKey.(*rsa.PrivateKey)
	decryptBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsedKey, data, nil)

	if err != nil {
		return nil, err
	}

	return decryptBytes, nil

}

func DecryptBox(gobText bytes.Buffer) ([]byte, error) {
	//first decode gob
	//Get Nonce, Key and Ciphertext from Gob
	//Decrypt with Secretbox
	gobs := gob.NewDecoder(&gobText)
	var encPayload EncryptPayload
	err := gobs.Decode(&encPayload)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encPayload.Ciphertext[:24])

	out, ok := secretbox.Open(nil, encPayload.Ciphertext[24:], encPayload.Nonce, encPayload.EncKey)
	if !ok {
		return nil, errors.New("unable to decrypt")
	}

	return out, nil

}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		key, _ := cmd.Flags().GetString("key")
		if key == "" {
			log.Fatal("Invalid key")
		}

		usr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		dbFile := fmt.Sprintf("%s/.tpass/noyb.db", usr.HomeDir)
		db, dbErr := pebble.Open(dbFile, &pebble.Options{})
		if dbErr != nil {
			log.Fatal("Unable to access or open database")
		}

		value, closer, valueErr := db.Get([]byte(key))
		if valueErr != nil {
			log.Fatal("Unable to fetch priv key")
		}

		if err := closer.Close(); err != nil {
			log.Fatal(err)
		}

		priv, closer, privErr := db.Get([]byte("priv"))
		if privErr != nil {
			log.Fatal("Unable to fetch priv key")
		}

		fmt.Println(string(priv))

		if err := closer.Close(); err != nil {
			log.Fatal(err)
		}

		//decrypt with private key
		//deserialize struct
		//decrypt symmetric
		unwrapped, err := DecryptWithPrivateKey(string(priv), value)
		if err != nil {
			log.Fatal(err)
		}

		var unwrap bytes.Buffer
		unwrap.WriteString(string(unwrapped))
		dec, err := DecryptBox(unwrap)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(dec))

	},
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringP("key", "k", "", "The key for which you'd like to retrieve the password value")
	getCmd.MarkFlagRequired("key")
}
