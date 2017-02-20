# checkocsp
Go Check OCSP state of a certificate

Work in progress, do not use in production.

## Example usage

From commandline, creating a JSON output.

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/checkocsp"
)

func main() {
	testsite := "binaryfigments.com"
	header, err := checkocsp.Run(testsite)
	json, err := json.MarshalIndent(header, "", "   ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(json))
}
```