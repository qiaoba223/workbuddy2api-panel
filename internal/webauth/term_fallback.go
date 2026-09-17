//go:build !linux

package webauth

import (
	"bufio"
	"os"
)

// IsTerminal 非 Linux 平台的保守实现：恒 false，走"按行读取"分支。
// 目标部署环境是 Linux 容器，此处只保证其他平台能编译通过。
func IsTerminal(fd int) bool { return false }

// ReadPassword 非 Linux 平台的降级实现：按行读取（**会回显**，调用方须提示用户）。
func ReadPassword(fd int) (string, error) {
	line, err := bufio.NewReader(os.NewFile(uintptr(fd), "stdin")).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return trimNewline(line), nil
}

// trimNewline 去掉行尾 CR/LF。
func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
