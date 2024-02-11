package cmd

import (
	"fmt"
	"log"
	"os"
	"os/user"

	"github.com/cockroachdb/pebble"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		confDir, _ := cmd.Flags().GetString("db")
		priv, _ := cmd.Flags().GetString("priv")
		pub, _ := cmd.Flags().GetString("pub")

		if _, err := os.Stat(priv); os.IsNotExist(err) {
			log.Fatal("private key does not exist")
		}

		if _, err := os.Stat(pub); os.IsNotExist(err) {
			log.Fatal("Public Key does not exist")
		}

		if _, err := os.Stat(confDir); os.IsNotExist(err) {
			dirErr := os.Mkdir(confDir, os.ModePerm)
			if dirErr != nil {
				log.Fatal("Unable to create configuration directory")
			}
			fmt.Println("[+] Successfully created conf directory")
			dbLoc := fmt.Sprintf("%s/noyb.db", confDir)
			db, dbCreateErr := pebble.Open(dbLoc, &pebble.Options{})
			if dbCreateErr != nil {
				log.Fatal("Unable to create database")
			}
			privKey := []byte("priv")
			if err := db.Set(privKey, []byte(priv), pebble.Sync); err != nil {
				log.Fatal("Unable to set the private key")
			}
			pubKey := []byte("pub")
			if err := db.Set(pubKey, []byte(pub), pebble.Sync); err != nil {
				log.Fatal("Unable to set the pub key")
			}
			fmt.Println("[+] TPass successfully initialized")
			if err := db.Close(); err != nil {
				log.Fatal(err)
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(initCmd)
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	rootDir := fmt.Sprintf("%s/.tpass", usr.HomeDir)
	defPriv := fmt.Sprintf("%s/.ssh/id_rsa", usr.HomeDir)
	defPub := fmt.Sprintf("%s/.ssh/id_rsa.pub", usr.HomeDir)
	initCmd.Flags().StringP("db", "d", rootDir, "Absolute path for the initialization directory and DB")
	initCmd.Flags().StringP("priv", "r", defPriv, "Location of private key. Resolves to $HOME/.ssh/id_rsa by default")
	initCmd.Flags().StringP("pub", "u", defPub, "Location of public key. Resolves to $HOME/.ssh/id_rsa.pub by default")
}
