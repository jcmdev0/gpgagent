// +build !windows

package gpgagent

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"net"
	"os"
	"strings"
)

// NewGpgAgentConn connects to the GPG Agent as described in the
// GPG_AGENT_INFO environment variable.
func NewGpgAgentConn() (*Conn, error) {
	var sp []string
	if runtimeFilePath, err := xdg.RuntimeFile("gnupg/S.gpg-agent"); err == nil {
		if _, err = os.Stat(runtimeFilePath); !errors.Is(err, os.ErrNotExist) {
			sp = append(sp, runtimeFilePath)
		}
	}
	if len(sp) == 0 {
		sp = strings.SplitN(os.Getenv("GPG_AGENT_INFO"), ":", 3)
		if len(sp) == 0 || len(sp[0]) == 0 {
			return nil, ErrNoAgent
		}
	}
	addr := &net.UnixAddr{Net: "unix", Name: sp[0]}
	uc, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(uc)
	lineb, err := br.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	line := string(lineb)
	if !strings.HasPrefix(line, "OK") {
		return nil, fmt.Errorf("gpgagent: didn't get OK; got %q", line)
	}
	return &Conn{uc, br}, nil
}
