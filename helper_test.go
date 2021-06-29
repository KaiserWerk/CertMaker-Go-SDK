package certmaker

import (
	"io/ioutil"
	"os"
	"testing"
)

func Test_fileExists(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "found", args: args{filename: "test.txt"}, want: true},
		{name: "not found", args: args{filename: "test2.txt"}, want: false},
	}
	for _, tt := range tests {
		if tt.want {
			_ = ioutil.WriteFile(tt.args.filename, []byte{0}, 0700)
		}
		t.Run(tt.name, func(t *testing.T) {
			if got := fileExists(tt.args.filename); got != tt.want {
				t.Errorf("fileExists() = %v, want %v", got, tt.want)
			}
		})
		_ = os.Remove(tt.args.filename)
	}
}
