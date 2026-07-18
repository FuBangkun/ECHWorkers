//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed wintun.dll
var wintunDLL []byte

// extractWintunDLL 将内嵌的 wintun.dll 提取到可执行文件同目录。
func extractWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	dllPath := filepath.Join(exeDir, "wintun.dll")

	// 如果 DLL 已存在且大小匹配则跳过
	if info, err := os.Stat(dllPath); err == nil && info.Size() == int64(len(wintunDLL)) {
		return nil
	}

	return os.WriteFile(dllPath, wintunDLL, 0644)
}
