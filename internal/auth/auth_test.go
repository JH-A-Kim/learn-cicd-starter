package auth

import (
	"testing"
	"net/http"
	err "errors"
)

func TestGetAPIKey(t *testing.T){
	tests := []struct {
		input http.Header
		want  string
		wantErr   error
	}{
		{input: http.Header{"Authorization": {""}}, want: "", wantErr: ErrNoAuthHeaderIncluded},
		{input: http.Header{"Authorization": {"notAPIkey"}}, want: "", wantErr: err.New("malformed authorization header")},
		{input: http.Header{"Authorization": {"ApiKey secret123"}}, want: "secret123", wantErr: nil},
	}
	for _, tc := range tests {
		got, err := GetAPIKey(tc.input)

		// Compare error messages (since two different error values may have same message)
		if (err == nil && tc.wantErr != nil) ||
			(err != nil && tc.wantErr == nil) ||
			(err != nil && tc.wantErr != nil && err.Error() != tc.wantErr.Error()) {
			t.Errorf("expected error %v, got %v", tc.wantErr, err)
		}

		if got != tc.want {
			t.Errorf("expected %q, got %q", tc.want, got)
		}
	}
}