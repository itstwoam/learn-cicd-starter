package auth

import (
	//"reflect"
	"testing"
	"net/http"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header http.Header
		want string
		expErr bool
	}{
		"Valid Bearer token": {
			header: http.Header{"Authorization": {"ApiKey abc123"}}, 
			want: "abc123", 
			expErr: true,
		},
		"Missing Authorization": {
			header: http.Header{},
			want: "",
			expErr: true,
		},
		"Empty Authorization": {
			header: http.Header{"Authorization": {""}},
			want: "",
			expErr: true,
		},
		"Malformed header with no space": {
			header: http.Header{"Authorization": {"ApiKey123"}},
			want: "",
			expErr: true,
		},
		"Multiple spaces": {
			header: http.Header{"Authorization": {"ApiKey abc123 extra"}},
			want: "abc123",
			expErr: false,
		},
		"Multiple authorization values": {
			header: http.Header{"Authorization": {"ApiKey abc123 Bearer def456"}},
			want: "abc123",
			expErr: false,
		},
		"Multiple authorization values with wrong order": {
			header: http.Header{"Authorization": {"Bearer def456 ApiKey abc123"}},
			want: "",
			expErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.header)

			if tc.expErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.expErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
