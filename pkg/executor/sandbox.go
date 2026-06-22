package executor

import (
	"fmt"
	"os/exec"
	"strings"
)

var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

func validateArgs(args []string) error {
	for _, arg := range args {
		for _, meta := range shellMetachars {
			if strings.Contains(arg, meta) {
				return fmt.Errorf("argument contains forbidden character %q: %s", meta, arg)
			}
		}
	}
	return nil
}

func applySandbox(cmd *exec.Cmd) {
	applySandboxOS(cmd)
}
