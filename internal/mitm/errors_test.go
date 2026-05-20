package mitm

import (
	"fmt"
	"testing"
)

func TestIsClientAbort(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "windows wsasend abort",
			err:  fmt.Errorf("write response to client: write tcp 127.0.0.1:8080->127.0.0.1:57488: wsasend: An established connection was aborted by the software in your host machine"),
			want: true,
		},
		{
			name: "upstream failure",
			err:  fmt.Errorf("upstream round trip: dial tcp: i/o timeout"),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClientAbort(tc.err); got != tc.want {
				t.Fatalf("isClientAbort() = %v, want %v", got, tc.want)
			}
		})
	}
}
