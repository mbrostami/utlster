package main

import (
	"reflect"
	"testing"
)

func Test_extractIPsFromCIDR(t *testing.T) {
	type args struct {
		ipRange string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "simple test",
			args: args{
				ipRange: "192.192.1.0/28",
			},
			want: []string{"192.192.1.0", "192.192.1.1", "192.192.1.2", "192.192.1.3", "192.192.1.4", "192.192.1.5", "192.192.1.6",
				"192.192.1.7", "192.192.1.8", "192.192.1.9", "192.192.1.10", "192.192.1.11", "192.192.1.12", "192.192.1.13", "192.192.1.14"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractIPsFromCIDR(tt.args.ipRange); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractIPsFromCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
