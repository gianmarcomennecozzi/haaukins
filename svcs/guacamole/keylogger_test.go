package guacamole_test

import (
	"bufio"
	"github.com/aau-network-security/go-ntp/store"
	"github.com/aau-network-security/go-ntp/svcs/guacamole"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyLogger(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	logpool, err := guacamole.NewKeyLoggerPool(tmpDir)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	team := store.Team{
		Id: "team",
	}

	logger, err := logpool.GetLogger(team)
	if err != nil {
		t.Fatalf("Unexpected error while getting logger: %s", err)
	}
	logger.Log([]byte("3.key,5.10000,1.0;"))
	logger.Log([]byte("5.mouse,3.100,4.1000,1.2;"))
	logger.Log([]byte("4.sync,8.31163115,8.31163115;"))

	time.Sleep(10 * time.Millisecond)

	expectedFn := filepath.Join(tmpDir, "team.log")
	f, err := os.Open(expectedFn)
	if err != nil {
		t.Fatalf("Failed to open file: %s", err)
	}

	nLines := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		scanner.Text()
		nLines++
	}
	if nLines != 2 {
		t.Fatalf("Expected 2 lines in log file, but got %d", nLines)
	}
}

func TestKeyFrameFilter(t *testing.T) {
	tt := []struct {
		name        string
		input       string
		expectedErr error
		expectedOk  bool
		key         guacamole.Element
		pressed     guacamole.Element
	}{
		{
			name:       "Normal",
			input:      "3.key,5.10000,1.0;",
			expectedOk: true,
			key:        "10000",
			pressed:    "0",
		},
		{
			name:       "Invalid opcode",
			input:      "5.mouse,3.100,4.1000,1.2;",
			expectedOk: false,
		},
		{
			name:        "Invalid number of args",
			input:       "3.key,5.10000;",
			expectedErr: guacamole.InvalidArgsErr,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			kff := guacamole.KeyFrameFilter{}

			rf := []byte(tc.input)
			kf, ok, err := kff.Filter(rf)
			if err != tc.expectedErr {
				t.Fatalf("Expected error (%t), but got: %s", tc.expectedErr, err)
			}
			if tc.expectedErr != nil {
				return
			}
			if ok != tc.expectedOk {
				t.Fatalf("Expected OK (%t), but got: %t", tc.expectedOk, ok)
			}
			if !tc.expectedOk {
				return
			}
			if kf.Key != tc.key {
				t.Fatalf("Expected key pressed to equal %s, but got %s", tc.key, kf.Key)
			}
			if kf.Pressed != tc.pressed {
				t.Fatalf("Expected key pressed to equal %s, but got %s", tc.pressed, kf.Pressed)
			}
		})
	}
}

func TestMouseFrameFilter(t *testing.T) {
	tt := []struct {
		name        string
		input       string
		expectedErr error
		expectedOk  bool
		x           guacamole.Element
		y           guacamole.Element
		button      guacamole.Element
	}{
		{
			name:       "Normal",
			input:      "5.mouse,3.100,4.1000,1.2;",
			expectedOk: true,
			x:          "100",
			y:          "1000",
			button:     "2",
		},
		{
			name:       "Invalid opcode",
			input:      "3.key,5.10000,1.0;",
			expectedOk: false,
		},
		{
			name:        "Invalid number of args",
			input:       "5.mouse,3.100,4.1000;",
			expectedErr: guacamole.InvalidArgsErr,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mff := guacamole.MouseFrameFilter{}

			rf := []byte(tc.input)
			mf, ok, err := mff.Filter(rf)
			if err != tc.expectedErr {
				t.Fatalf("Expected error (%t), but got: %s", tc.expectedErr, err)
			}
			if tc.expectedErr != nil {
				return
			}
			if ok != tc.expectedOk {
				t.Fatalf("Expected OK (%t), but got: %t", tc.expectedOk, ok)
			}
			if !tc.expectedOk {
				return
			}
			if mf.X != tc.x {
				t.Fatalf("Expected x to equal %s, but got %s", tc.x, mf.X)
			}
			if mf.Y != tc.y {
				t.Fatalf("Expected x to equal %s, but got %s", tc.y, mf.Y)
			}
			if mf.Button != tc.button {
				t.Fatalf("Expected button to equal %s, but got %s", tc.button, mf.Button)
			}
		})
	}
}
