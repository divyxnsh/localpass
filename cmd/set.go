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
	"io"
	"io/ioutil"
	"log"
	"os/user"

	"github.com/cockroachdb/pebble"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
)

const (
	KeySize   = 32
	NonceSize = 24
)

// EncryptPayload => This gets serialized into gob
type EncryptPayload struct {
	EncKey     *[32]byte
	Nonce      *[24]byte
	Ciphertext []byte
}

func passwordPrompt() string {
	passPrompt := promptui.Prompt{
		Label: "Enter Password",
		Mask:  '*',
	}

	password, err := passPrompt.Run()
	if err != nil {
		log.Fatal("Unable to read password")
	}
	return password
}

// GenerateSessKey => Generates Symmetric Encryptio Key for Password
func GenerateSessKey() (*[KeySize]byte, error) {
	key := new([KeySize]byte)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateNonce => Generates a Nonce for the Encryption
func GenerateNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

// EncryptData => Encrypts the data that is given to it
func EncryptData(message []byte) ([]byte, *[KeySize]byte, *[NonceSize]byte, error) {
	nonce, nerr := GenerateNonce()
	if nerr != nil {
		return nil, nil, nil, errors.New("Unable to generate Nonce for the encryption Process")
	}
	key, kerr := GenerateSessKey()
	if kerr != nil {
		return nil, nil, nil, errors.New("Unable to generate Key for the encryption Process")
	}

	ciphertext := make([]byte, len(nonce))
	copy(ciphertext, nonce[:])
	ciphertext = secretbox.Seal(ciphertext, message, nonce, key)

	return ciphertext, key, nonce, nil

}

// EncryptWithPublicKey => This functions finds the public key and uses that to wrap the already encrypted symmetric ciphertext
func EncryptWithPublicKey(pubKeyLoc string, symCipherText bytes.Buffer) ([]byte, error) {
	//read file first
	pub, err := ioutil.ReadFile(pubKeyLoc)
	if err != nil {
		return nil, err
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		return nil, err
	}

	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	rsaPub := pubCrypto.(*rsa.PublicKey)

	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, symCipherText.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	return encryptedBytes, nil

}

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		pwd, _ := cmd.Flags().GetString("password")
		key, _ := cmd.Flags().GetString("key")
		if pwd == "" {
			pwd = passwordPrompt()
		}

		cipher, encKey, nonce, err := EncryptData([]byte(pwd))
		if err != nil {
			log.Fatal(err)
		}
		var encPayload bytes.Buffer
		gobs := gob.NewEncoder(&encPayload)

		encErr := gobs.Encode(EncryptPayload{encKey, nonce, cipher})
		if encErr != nil {
			log.Fatal(encErr)
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

		value, closer, valueErr := db.Get([]byte("pub"))
		if valueErr != nil {
			log.Fatal("Unable to fetch priv key")
		}

		if err := closer.Close(); err != nil {
			log.Fatal(err)
		}

		enc, err := EncryptWithPublicKey(string(value), encPayload)
		if err != nil {
			log.Fatal(err)
		}
		if err := db.Set([]byte(key), []byte(base64.StdEncoding.EncodeToString(enc)), pebble.Sync); err != nil {
			log.Fatal("Unable to write value to DB")
		}
		fmt.Printf("[+] Successfully stored and protected value for key: '%s'\n", key)
		if err := db.Close(); err != nil {
			log.Fatal(err)
		}

	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().StringP("key", "k", "", "Key that you want to use for your password. It needs to be unique. Use namespaces if possible")
	setCmd.Flags().StringP("password", "p", "", "Password that you want to store and protect")
	setCmd.MarkFlagRequired("key")
}
