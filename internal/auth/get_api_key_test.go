package auth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input         http.Header
		want          string
		errorExpected bool
	}{
		"empty header": {
			input:         http.Header{},
			want:          "",
			errorExpected: true,
		},
		"no authorization header": {
			input:         http.Header{"Content-Type": []string{"application/json"}},
			want:          "",
			errorExpected: true,
		},
		"malformed authorization header": {
			input:         http.Header{"Authorization": []string{"HouseKey metalkey"}},
			want:          "",
			errorExpected: true,
		},
		"correct authorization header": {
			input:         http.Header{"Authorization": []string{"ApiKey your_api_key_here"}},
			want:          "your_api_key_here",
			errorExpected: false,
		},
	}

	for name, tc := range tests {
		got, err := GetAPIKey(tc.input)
		if err == nil && tc.errorExpected {
			t.Fatalf("%s: expected an error, but no error returned", name)
		}

		if err != nil && !tc.errorExpected {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		if got != tc.want {
			t.Fatalf("%s: expected: %v, got: %v", name, tc.want, got)
		}
	}

}

func TestGetAPIKeySoln(t *testing.T) {
	tests := []struct {
		key       string
		value     string
		expect    string
		expectErr string
	}{
		{
			expectErr: "no authorization header",
		},
		{
			key:       "Authorization",
			expectErr: "no authorization header",
		},
		{
			key:       "Authorization",
			value:     "-",
			expectErr: "malformed authorization header",
		},
		{
			key:       "Authorization",
			value:     "Bearer xxxxxx",
			expectErr: "malformed authorization header",
		},
		{
			key:       "Authorization",
			value:     "ApiKey xxxxxx",
			expect:    "xxxxxx",
			expectErr: "not expecting an error",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("TestGetAPIKey Case #%v:", i), func(t *testing.T) {
			header := http.Header{}
			header.Add(test.key, test.value)

			output, err := GetAPIKey(header)
			if err != nil {
				if strings.Contains(err.Error(), test.expectErr) {
					return
				}
				t.Errorf("Unexpected: TestGetAPIKey:%v\n", err)
				return
			}

			if output != test.expect {
				t.Errorf("Unexpected: TestGetAPIKey:%s", output)
				return
			}
		})
	}
}
