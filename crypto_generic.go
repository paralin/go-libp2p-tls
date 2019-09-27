//go:build js
// +build js

package libp2ptls

// We want nodes without AES hardware (e.g. ARM) support to always use ChaCha.
// Only if both nodes have AES hardware support (e.g. x86), AES should be used.
// x86->x86: AES, ARM->x86: ChaCha, x86->ARM: ChaCha and ARM->ARM: Chacha
// This function returns true if we don't have AES hardware support, and false otherwise.
// Thus, ARM servers will always use their own cipher suite preferences (ChaCha first),
// and x86 servers will aways use the client's cipher suite preferences.
func preferServerCipherSuites() bool {
	// Copied from the Go TLS implementation.

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = false // cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = false // cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		hasGCMAsmS390X = false // cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)
	return !hasGCMAsm
}
