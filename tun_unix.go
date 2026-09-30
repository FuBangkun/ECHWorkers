//go:build darwin || linux

package main

import "os/exec"

// runCmd 执行命令并忽略输出与错误（用于尽力而为的清理操作）。
func runCmd(name string, args ...string) {
	exec.Command(name, args...).Run()
}

// runCmdOutput 执行命令并返回合并后的 stdout+stderr。
func runCmdOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// runCmdStdout 执行命令并仅返回 stdout。
func runCmdStdout(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}
