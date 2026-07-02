package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/exilens/xns-i2p/i2p"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xns-i2p:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("command is required")
	}

	switch args[0] {
	case "address":
		if len(args) != 2 {
			return errors.New("usage: xns-i2p address OWNER_KEY")
		}
		public, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("owner key: %w", err)
		}
		address, err := i2p.Address(public)
		if err != nil {
			return err
		}
		fmt.Println(address)
		return nil

	case "owner":
		if len(args) != 2 {
			return errors.New("usage: xns-i2p owner I2P_ADDRESS")
		}
		public, err := i2p.PublicKey(args[1])
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(public))
		return nil

	case "service":
		if len(args) != 3 {
			return errors.New("usage: xns-i2p service PRIVATE_KEY.pem DIRECTORY")
		}
		service, err := i2p.ServiceFromPEM(args[1])
		if err != nil {
			return err
		}
		if err := i2p.WriteService(args[2], service); err != nil {
			return err
		}
		printService(service)
		return nil

	case "from-tor":
		if len(args) != 3 {
			return errors.New("usage: xns-i2p from-tor TOR_DIRECTORY PRIVATE_DAT")
		}
		service, err := i2p.ServiceFromTorDirectory(args[1])
		if err != nil {
			return err
		}
		if err := i2p.WritePrivateDat(args[2], service); err != nil {
			return err
		}
		printService(service)
		return nil

	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: xns-i2p inspect DIRECTORY")
		}
		service, err := i2p.ReadService(args[1])
		if err != nil {
			return err
		}
		printService(service)
		return nil

	case "help", "-h", "--help":
		usage()
		return nil

	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printService(service i2p.Service) {
	fmt.Printf("owner_key: %s\n", hex.EncodeToString(service.PublicKey))
	fmt.Printf("i2p_address: %s\n", service.Address)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  xns-i2p address OWNER_KEY
  xns-i2p owner I2P_ADDRESS
  xns-i2p service PRIVATE_KEY.pem DIRECTORY
  xns-i2p from-tor TOR_DIRECTORY PRIVATE_DAT
  xns-i2p inspect DIRECTORY`)
}
