package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// usage: validator [input.json]
// Reads the request document from the file argument, or stdin when omitted.
// Exit codes: 0 authorized, 1 unauthorized, 2 rejected batch / bad input.
func main() {
	var data []byte
	var err error
	switch len(os.Args) {
	case 1:
		data, err = io.ReadAll(os.Stdin)
	case 2:
		data, err = os.ReadFile(os.Args[1])
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [input.json]\n", os.Args[0])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(2)
	}

	var in Input
	if err := json.Unmarshal(data, &in); err != nil {
		emit(Result{Status: StatusRejected, Reason: "invalid JSON input: " + err.Error()})
		os.Exit(2)
	}

	res := Validate(&in)
	emit(res)
	switch res.Status {
	case StatusAuthorized:
		os.Exit(0)
	case StatusUnauthorized:
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func emit(res Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(2)
	}
}
