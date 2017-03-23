package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/binaryfigments/checkocsp"
)

func main() {
	checkHost := flag.String("hostname", "", "The fqdn of the host to check for OCSP. (Required)")
	flag.Parse()
	if *checkHost == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ocsp, err := checkocsp.Run(*checkHost)
	json, err := json.MarshalIndent(ocsp, "", "   ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", json)
	os.Exit(0)
}
