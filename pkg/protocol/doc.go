// Package protocol defines the Quantum-Go wire format: the stream message codec
// (hellos, finished messages, data, alerts and rekey), the self-contained datagram
// frame codec, and the protocol version. Parsers here read bytes from the network
// before any authentication, so they are bounds-checked and fuzzed.
package protocol
