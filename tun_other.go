//go:build !windows

package main

func configureTUN(tunName, serverIP string) error {
	return nil
}

func cleanupTUN(tunName string) {}

func getOriginalGateway() string {
	return ""
}

func trimString(s string) string {
	return s
}
