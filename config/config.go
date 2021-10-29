package config

import (
	"log"
	"os"
)

/*
	Check for an environment variable value, if absent use a default value
*/
func OptionalEnv(varName string, optional string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		return optional
	}
	return envVar
}

/*
	Check for an environment variable value, exit program if not found
*/
func RequiredEnv(varName string) string {
	envVar := os.Getenv(varName)
	if envVar == "" {
		log.Fatalf("The required env var %s is not provided. Exiting", varName)
	}
	return envVar
}

/*
	Check for an environment variable value with expected possibilities, exit program if value not expected
*/
func ExpectedEnv(varName string, expected []string) string {
	envVar := RequiredEnv(varName)
	if !contains(expected, envVar) {
		log.Fatalf("The value for env var %s is not expected. Expected values are %v", varName, expected)
	}
	return envVar
}

func contains(source []string, target string) bool {
	for _, a := range source {
		if a == target {
			return true
		}
	}
	return false
}
