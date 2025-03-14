# oniongen-go

v3 .onion address vanity URL generator written in Go with Bitcoin Core integration.

This implementation generates random ed25519 keys across all CPU cores. The ed25519 public key is converted to a Tor v3 .onion address which is then compared to a user supplied regex to find a vanity URL. The program supports both standard Tor format and Bitcoin Core format output. It terminates when the user-supplied number of addresses have been generated.

## Features

- **Parallel Processing**: Utilizes all CPU cores for faster generation
- **Dual Output Modes**:
  - **Tor Mode**: Generates keys in Tor's native format (default)
  - **Bitcoin Mode**: Generates keys in Bitcoin Core's expected format
- **Flexible Matching**: Uses regular expressions for advanced pattern matching
- **Secure**: Uses cryptographically secure random number generation

## Usage

```
go run main.go [options] <regex> <number>
```

### Arguments

- `regex`: Regular expression pattern addresses should match (consists of base32 characters: a-z, 2-7)
- `number`: Number of matching addresses to generate before exiting

### Options

- `-mode`: Output mode: 'tor' (default) or 'bitcoin'
- `-output`: Output file path (for bitcoin mode)

## Examples

### Generate Tor-compatible keys (default)

```
go run main.go "^test" 5
```

This generates 5 onion addresses starting with "test" and saves them in Tor's native format.
Each address is saved in its own directory with the required files: `hs_ed25519_secret_key`, `hs_ed25519_public_key`, and `hostname`.

### Generate Bitcoin Core-compatible key

```
go run main.go -mode=bitcoin "^btc" 1
```

This generates an onion address starting with "btc" and saves the private key in Bitcoin Core's format (`ED25519-V3:{base64-encoded-key}`) to a file named `onion_v3_private_key` in the current directory.

### Generate Bitcoin Core-compatible key with custom output location

```
go run main.go -mode=bitcoin -output=/path/to/bitcoin/datadir/onion_v3_private_key "^btc" 1
```

This generates an onion address starting with "btc" and saves the private key in Bitcoin Core's format to the specified file path.

## Output Formats

### Tor Format (default)

Keys are saved in Tor's native format with appropriate file structure for direct use with Tor hidden services. The following files are created in a directory named after the onion address:
- `hs_ed25519_secret_key`: The private key in Tor's format
- `hs_ed25519_public_key`: The public key
- `hostname`: The .onion address

### Bitcoin Format

Keys are saved in Bitcoin Core's expected format: `ED25519-V3:{base64-encoded-key}`. This format is compatible with Bitcoin Core's Tor hidden service integration and can be used directly as the `onion_v3_private_key` file.

## References

- public key -> onion: https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2136-L2158
- secret key expansion:
    - implementation in mkp224o: https://github.com/cathugger/mkp224o/blob/af5a7cfe122ba62e819b92c8b5a662151a284c69/ed25519/ed25519.h#L153-L161
    - possibly related: https://github.com/torproject/torspec/blob/12271f0e6db00dee9600425b2de063e02f19c1ee/rend-spec-v3.txt#L2268-L2327 ??
- Bitcoin Core Tor integration: https://github.com/bitcoin/bitcoin/blob/master/doc/tor.md

## Bitcoin Core Integration

To use a generated vanity address with Bitcoin Core:

1. Generate a key using the Bitcoin mode:
   ```
   go run main.go -mode=bitcoin -output=/path/to/bitcoin/datadir/onion_v3_private_key "^yourprefix" 1
   ```

2. Restart Bitcoin Core with Tor enabled:
   ```
   bitcoind -daemon -proxy=127.0.0.1:9050 -listen=1 -listenonion=1
   ```

3. Bitcoin Core will automatically use the key found in `onion_v3_private_key` to establish the hidden service with your desired vanity address.
