package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// 1. Define the structure for individual test cases
	type testCase struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}

	// 2. Build the table of test conditions
	tests := []testCase{
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret_token_12345"},
			},
			expectedKey:   "secret_token_12345",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header (No Space)",
			headers: http.Header{
				"Authorization": []string{"ApiKey_secret_token_12345"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header (Wrong Prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer secret_token_12345"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// 3. Iterate through the table execution matrix
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualKey, err := GetAPIKey(tc.headers)

			// Validate key outputs
			if actualKey != tc.expectedKey {
				t.Errorf("GetAPIKey() returned key %q, want %q", actualKey, tc.expectedKey)
			}

			// Validate error matching
			if tc.expectedError != nil {
				if err == nil || err.Error() != tc.expectedError.Error() {
					t.Errorf("GetAPIKey() returned error %v, want %v", err, tc.expectedError)
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() returned unexpected error: %v", err)
			}
		})
	}
}
