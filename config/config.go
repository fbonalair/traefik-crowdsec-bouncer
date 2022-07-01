package config

import (
	"log"
	"os"
	"strconv"
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

/*
	Function for custom validation of configuration that will panic if values are not expected.
	//FIXME it's a first start before centralizing configuration then injection of dependency.
*/
func ValidateEnv() {
	// Validate Ban response code is a valid http response code
	banResponseCode := OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "403")
	parsedCode, err := strconv.Atoi(banResponseCode)
	if err != nil {
		log.Fatalf("The value for env var %s is not an int. It should be a valid http response code.", "CROWDSEC_BOUNCER_BAN_RESPONSE_CODE")
	}
	if parsedCode < 100 || parsedCode > 599 {
		log.Fatalf("The value for env var %s should be a valid http response code between 100 and 599 included.", "CROWDSEC_BOUNCER_BAN_RESPONSE_CODE")
	}
}
