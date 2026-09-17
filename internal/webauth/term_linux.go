//go:build linux

package webauth

import (
	"bufio"
	"os"

	"golang.org/x/sys/unix"
)

// IsTerminal 报告 fd 是否连着一个终端。
func IsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// ReadPassword 关闭终端回显读一行密码。
//
// 为什么不回显很重要：docker exec 的终端会保留 scrollback，密码明文留在屏幕上
// 等于写进 shell 历史与终端缓冲区；关掉 ECHO 后输入不可见，进程退出前恢复原状态
// （defer 保证异常路径也恢复，否则终端会一直吞掉用户输入）。
func ReadPassword(fd int) (string, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	noecho := *old
	noecho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noecho); err != nil {
		return "", err
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }()

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
