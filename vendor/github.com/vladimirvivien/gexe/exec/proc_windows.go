//go:build windows

package exec

// applyCredentials is a no-op as this works vastly different on Windows.
func (p *Proc) applyCredentials() {
	// Windows doesn't support user/group IDs in the same way {Li|U}nix does.
	// Windows impersonation will not be supported in this package a this time.
}
