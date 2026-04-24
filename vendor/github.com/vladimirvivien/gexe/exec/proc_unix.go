//go:build !windows

package exec

import (
	"syscall"
)

// applyCredentials applies the user and group IDs to the command.
func (p *Proc) applyCredentials() {
	// apply user id and user grp
	var procCred *syscall.Credential
	if p.userid != nil {
		procCred = &syscall.Credential{
			Uid: uint32(*p.userid),
		}
	}
	if p.groupid != nil {
		if procCred == nil {
			procCred = new(syscall.Credential)
		}
		procCred.Gid = uint32(*p.groupid)
	}
	if procCred != nil {
		if p.cmd.SysProcAttr == nil {
			p.cmd.SysProcAttr = new(syscall.SysProcAttr)
		}
		p.cmd.SysProcAttr.Credential = procCred
	}
}
