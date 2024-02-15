package fuzzer_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/CyberRoute/bruter/pkg/fuzzer"
)

func TestReader(t *testing.T) {
	// Create a temporary file with some content
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up the file

	// Write some content to the file
	content := "line1\nline2\nline3\n"
	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Test the Reader function with default offset (0)
	ch, offset, err := fuzzer.Reader(tmpfile.Name(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 {
		t.Errorf("Expected default offset should be %d", offset)
	}

	// Read all lines from the channel into a slice
	var lines []string
	for line := range ch {
		lines = append(lines, line)
	}

	// Verify the lines read from the channel
	expectedLines := []string{"line1", "line2", "line3"}
	if !reflect.DeepEqual(lines, expectedLines) {
		t.Errorf("Expected lines %v, got %v", expectedLines, lines)
	}
}
