package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	test := []struct {
		name     string
		header   http.Header
		err      error
		expected string
	}{
		{
			name: "should return the api key",
			header: http.Header{
				"Authorization": []string{"ApiKey 1234567890"},
			},
			err:      nil,
			expected: "1234567890",
		},
		{
			name: "not ApiKey prefix",
			header: http.Header{
				"Authorization": {"Bearer 892839832"},
			},
			err:      errors.New("malformed authorization header"),
			expected: "",
		},
		{
			name: "empty authorization header",
			header: http.Header{
				"Authorization": []string{""},
			},
			err:      ErrNoAuthHeaderIncluded,
			expected: "",
		},
		{
			name:     "nil header",
			header:   nil,
			err:      ErrNoAuthHeaderIncluded,
			expected: "",
		},
		{
			name: "header split less than 2",
			header: http.Header{
				"Authorization": {"ApiKey"},
			},
			err:      errors.New("malformed authorization header"),
			expected: "",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.header)
			if err != nil {
				if tt.err == nil {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.err)
					return
				} else {
					if err.Error() != tt.err.Error() {
						t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.err)
						return
					}
				}
			}
			if got != tt.expected {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}
