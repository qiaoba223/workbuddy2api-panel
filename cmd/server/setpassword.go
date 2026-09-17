// setpassword.go 面板账密登录的用户管理子命令。
//
// 用途（**引导入口**）：面板首次启用账密登录时，config.json 里还没有任何用户，
// 此时没有"已登录"的人能去调面板的用户管理接口——形成鸡生蛋问题。本子命令从
// 宿主机侧直接操作用户库文件，解决引导；之后的日常改密/增删用户都走面板 UI。
//
// 用法（在容器内执行）：
//
//	docker exec -it workbuddy2api /app/wb2api setpassword <用户名>
//	docker exec -it workbuddy2api /app/wb2api setpassword <用户名> --password <密码>
//	docker exec -it workbuddy2api /app/wb2api setpassword --list
//	docker exec -it workbuddy2api /app/wb2api setpassword --delete <用户名>
//
// 密码交互式读取（不回显、不进 shell 历史）；--password 供脚本化使用（会进历史，
// 仅限受控环境）。
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/webauth"
)

// runSetPassword 处理 setpassword 子命令；返回进程退出码。
func runSetPassword(cfgPath string, args []string) int {
	cfg, err := Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取配置失败 %s: %v\n", cfgPath, err)
		return 1
	}

	// 用户库路径解析（与 main 一致：config 相对路径按 config 所在目录解析）。
	usersFile := cfg.WebAuth.UsersFile
	if usersFile == "" {
		usersFile = filepath.Join(filepath.Dir(cfgPath), "data", "web_users.json")
	} else if !filepath.IsAbs(usersFile) {
		usersFile = filepath.Join(filepath.Dir(cfgPath), usersFile)
	}

	// --list：列出既有用户。
	if len(args) > 0 && (args[0] == "--list" || args[0] == "-l") {
		users, err := webauth.LoadUsers(usersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取用户库失败: %v\n", err)
			return 1
		}
		if len(users) == 0 {
			fmt.Printf("用户库 %s 为空（尚无任何面板登录用户）\n", usersFile)
			return 0
		}
		fmt.Printf("用户库 %s：\n", usersFile)
		for u := range users {
			fmt.Printf("  - %s\n", u)
		}
		return 0
	}

	// --delete <用户名>：删除用户。
	if len(args) > 0 && args[0] == "--delete" {
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法：setpassword --delete <用户名>")
			return 2
		}
		users, err := webauth.LoadUsers(usersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取用户库失败: %v\n", err)
			return 1
		}
		name := args[1]
		if _, ok := users[name]; !ok {
			fmt.Fprintf(os.Stderr, "用户 %q 不存在\n", name)
			return 1
		}
		delete(users, name)
		if err := webauth.SaveUsers(usersFile, users); err != nil {
			fmt.Fprintf(os.Stderr, "落盘失败: %v\n", err)
			return 1
		}
		fmt.Printf("已删除用户 %q（重启容器后其会话全部失效）\n", name)
		return 0
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法：setpassword <用户名> [--password <密码>] | --list | --delete <用户名>")
		return 2
	}

	username := strings.TrimSpace(args[0])
	if username == "" || strings.HasPrefix(username, "-") {
		fmt.Fprintln(os.Stderr, "用户名不能为空或以 - 开头")
		return 2
	}

	// 取密码：--password 显式给出，否则交互式读两次（不回显）。
	password := ""
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == "--password" || rest[i] == "-p" {
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "--password 后需要跟密码")
				return 2
			}
			password = rest[i+1]
			break
		}
	}
	if password == "" {
		var err error
		password, err = promptPasswordTwice()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
	}
	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "密码至少 8 位")
		return 2
	}

	hash, err := webauth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成哈希失败: %v\n", err)
		return 1
	}
	users, err := webauth.LoadUsers(usersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取用户库失败: %v\n", err)
		return 1
	}
	_, existed := users[username]
	users[username] = hash
	if err := webauth.SaveUsers(usersFile, users); err != nil {
		fmt.Fprintf(os.Stderr, "落盘失败: %v\n", err)
		return 1
	}

	action := "已创建"
	if existed {
		action = "已更新密码"
	}
	fmt.Printf("%s用户 %q（用户库 %s）\n", action, username, usersFile)
	if !cfg.WebAuth.Enabled {
		fmt.Println("提示：config.json 里 web_auth.enabled 仍为 false，账密登录尚未生效——请改为 true 并重启。")
	} else {
		fmt.Println("提示：若服务正在运行，重启容器后新密码生效（会话存储在内网，重启即清空）。")
	}
	return 0
}

// promptPasswordTwice 交互式读密码（不回显），两次输入需一致。
func promptPasswordTwice() (string, error) {
	fd := int(os.Stdin.Fd())
	if !webauth.IsTerminal(fd) {
		// 非终端（如 docker exec 未加 -it）：退回按行读一次，提示用户注意历史记录。
		fmt.Fprintln(os.Stderr, "提示：非交互式终端，将从标准输入读一行作为密码（注意 shell 历史）。")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("读取密码失败: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Print("请输入新密码（至少 8 位）: ")
	first, err := webauth.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	fmt.Print("请再次输入以确认: ")
	second, err := webauth.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	if first != second {
		return "", fmt.Errorf("两次输入不一致")
	}
	return first, nil
}
