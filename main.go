package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

// PrefixMatch represents a matched prefix and its corresponding onion address and key
type PrefixMatch struct {
	Prefix      string
	OnionAddr   string
	PrivateKey  string
	Attempts    uint64
	ElapsedTime time.Duration
}

// Output mode constants
const (
	TorMode     = "tor"
	BitcoinMode = "bitcoin"
)

func generate(wg *sync.WaitGroup, re *regexp.Regexp, prefixes []string, outputMode string, outputPath string, resultChan chan PrefixMatch) {
	var attempts uint64
	startTime := time.Now()

	for {
		// Use crypto/rand explicitly for secure random generation
		publicKey, secretKey, err := ed25519.GenerateKey(rand.Reader)
		checkErr(err)

		atomic.AddUint64(&attempts, 1)
		onionAddress := encodePublicKey(publicKey)

		// If prefixes are provided, check against them
		if len(prefixes) > 0 {
			for _, prefix := range prefixes {
				if strings.HasPrefix(onionAddress, prefix) {
					match := PrefixMatch{
						Prefix:      prefix,
						OnionAddr:   onionAddress,
						PrivateKey:  base64.StdEncoding.EncodeToString(secretKey[:32]),
						Attempts:    attempts,
						ElapsedTime: time.Since(startTime),
					}
					resultChan <- match
					break
				}
			}
		} else if re != nil && re.MatchString(onionAddress) {
			// If using regex pattern
			fmt.Println(onionAddress)
			match := PrefixMatch{
				Prefix:      "",
				OnionAddr:   onionAddress,
				PrivateKey:  base64.StdEncoding.EncodeToString(secretKey[:32]),
				Attempts:    attempts,
				ElapsedTime: time.Since(startTime),
			}

			if outputMode == TorMode {
				saveTorFormat(onionAddress, publicKey, expandSecretKey(secretKey))
			}

			resultChan <- match
		}
	}
}

func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {

	hash := sha512.Sum512(secretKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash

}

func encodePublicKey(publicKey ed25519.PublicKey) string {

	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)

}

func saveTorFormat(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)

	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600))

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600))

	checkErr(ioutil.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion\n"), 0600))
}

func saveBitcoinFormatMulti(matches []PrefixMatch, outputPath string) {
	// Determine the output location
	var outputFile string
	if outputPath == "" {
		// Default to current directory if not specified
		outputFile = "onion_v3_private_key"
	} else {
		outputFile = outputPath
	}

	// Create or truncate the output file
	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error opening output file %s: %v\n", outputFile, err)
		os.Exit(1)
	}
	defer file.Close()

	// Write each key to the file
	writer := bufio.NewWriter(file)
	for _, match := range matches {
		// Encode the key in the format Bitcoin Core expects
		bitcoinKeyFormat := "ED25519-V3:" + match.PrivateKey + "\n"

		_, err := writer.WriteString(bitcoinKeyFormat)
		if err != nil {
			fmt.Printf("Error writing to file %s: %v\n", outputFile, err)
			os.Exit(1)
		}

		fmt.Printf("Generated address: %s.onion", match.OnionAddr)
		if match.Prefix != "" {
			fmt.Printf(" (matched prefix: %s)", match.Prefix)
		}
		fmt.Printf(" after %d attempts (%.2f/sec)\n",
			match.Attempts, float64(match.Attempts)/match.ElapsedTime.Seconds())
	}

	// Flush the writer to ensure all data is written
	err = writer.Flush()
	if err != nil {
		fmt.Printf("Error flushing data to file %s: %v\n", outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("Bitcoin format keys saved to %s\n", outputFile)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func printUsage() {
	fmt.Println("Vanity Onion Address Generator")
	fmt.Println("\nUsage:")
	fmt.Println("  oniongen-go [options] <regex> <number>")
	fmt.Println("\nArguments:")
	fmt.Println("  regex    - Regular expression pattern addresses should match (base32 chars: a-z, 2-7)")
	fmt.Println("           - Not required if using -prefixfile")
	fmt.Println("  number   - Number of matching addresses to generate before exiting")
	fmt.Println("\nOptions:")
	fmt.Println("  -mode       - Output mode: 'tor' (default) or 'bitcoin'")
	fmt.Println("  -output     - Output file path (for bitcoin mode)")
	fmt.Println("  -prefixfile - Path to file containing address prefixes (one per line)")
	fmt.Println("                If provided, regex argument is ignored")
	fmt.Println("\nExamples:")
	fmt.Println("  oniongen-go \"^test\" 5                        # Generate 5 addresses starting with 'test' in Tor format")
	fmt.Println("  oniongen-go -mode=bitcoin \"^btc\" 1            # Generate 1 address starting with 'btc' in Bitcoin format")
	fmt.Println("  oniongen-go -mode=bitcoin -output=/path/to/onion_v3_private_key \"^btc\" 1")
	fmt.Println("  oniongen-go -mode=bitcoin -prefixfile=prefixes.txt 5  # Generate 5 addresses with prefixes from file")
	fmt.Println("\nReferences:")
	fmt.Println("  - Tor v3 onion address specification: https://github.com/torproject/torspec/blob/master/rend-spec-v3.txt")
}

// readPrefixFile reads prefixes from a file (one per line)
func readPrefixFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("cannot open prefix file: %v", err)
	}
	defer file.Close()

	var prefixes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		prefix := strings.TrimSpace(scanner.Text())
		if prefix != "" {
			prefixes = append(prefixes, prefix)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading prefix file: %v", err)
	}

	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no valid prefixes found in file")
	}

	return prefixes, nil
}

func main() {
	// Define command-line flags
	outputMode := flag.String("mode", TorMode, "Output mode: 'tor' or 'bitcoin'")
	outputPath := flag.String("output", "", "Output file path (for bitcoin mode)")
	prefixFilePath := flag.String("prefixfile", "", "Path to file containing address prefixes (one per line)")

	// Custom usage message
	flag.Usage = printUsage
	flag.Parse()

	args := flag.Args()

	// Validate the output mode
	if *outputMode != TorMode && *outputMode != BitcoinMode {
		fmt.Printf("Invalid output mode: %s. Must be 'tor' or 'bitcoin'\n", *outputMode)
		printUsage()
		os.Exit(1)
	}

	var pattern string
	var number int
	var prefixes []string
	var err error

	// Check if we're using prefixes from a file
	if *prefixFilePath != "" {
		prefixes, err = readPrefixFile(*prefixFilePath)
		if err != nil {
			fmt.Printf("Error reading prefix file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Loaded %d prefixes from %s\n", len(prefixes), *prefixFilePath)

		// With prefix file, we just need the number argument
		if len(args) < 1 {
			fmt.Println("Error: Missing number of addresses to generate")
			printUsage()
			os.Exit(1)
		}

		num, err := strconv.Atoi(args[0])
		if err != nil || num < 1 {
			fmt.Println("Error: Number of addresses must be a positive integer")
			printUsage()
			os.Exit(1)
		}
		number = num
	} else {
		// Without prefix file, we need both regex and number arguments
		if len(args) < 2 {
			fmt.Println("Error: Missing required arguments")
			printUsage()
			os.Exit(1)
		}

		pattern = args[0]
		num, err := strconv.Atoi(args[1])
		if err != nil || num < 1 {
			fmt.Println("Error: Number of addresses must be a positive integer")
			printUsage()
			os.Exit(1)
		}
		number = num
	}

	// Create a regex pattern if we're not using prefixes from a file
	var re *regexp.Regexp
	if len(prefixes) == 0 {
		re, err = regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("Invalid regular expression: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Generating %d addresses with %d CPU cores\n", number, runtime.NumCPU())

	// Create a channel for results and start a goroutine for each CPU core
	resultChan := make(chan PrefixMatch, number)
	var wg sync.WaitGroup

	// Keep track of all generated matches
	var matches []PrefixMatch
	var matchCount int32

	// Start goroutine to collect results
	go func() {
		for match := range resultChan {
			matches = append(matches, match)
			atomic.AddInt32(&matchCount, 1)

			// If we've found enough matches, exit
			if atomic.LoadInt32(&matchCount) >= int32(number) {
				// In Bitcoin mode, save all matches to a single file
				if *outputMode == BitcoinMode {
					saveBitcoinFormatMulti(matches, *outputPath)
				}
				os.Exit(0)
			}
		}
	}()

	// Start worker goroutines
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go generate(&wg, re, prefixes, *outputMode, *outputPath, resultChan)
	}

	// Wait for all workers to complete (this will never happen in normal circumstances)
	wg.Wait()
}
