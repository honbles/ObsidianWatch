package parser

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestScanSyslogLinesReassemblesSplitReads(t *testing.T) {
	in := "<34>first message\n\n<34>second message\r\n<34>third no newline"
	var got []string
	// OneByteReader delivers one byte per Read, the worst case for chunk-splitting.
	if err := ScanSyslogLines(iotest.OneByteReader(strings.NewReader(in)), func(l string) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	want := []string{"<34>first message", "<34>second message", "<34>third no newline"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %q", got)
	}
}

func TestScanSyslogLinesRejectsOversizedLine(t *testing.T) {
	err := ScanSyslogLines(io.MultiReader(strings.NewReader(strings.Repeat("a", MaxSyslogLine+10))), func(string) {})
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("err = %v, want ErrTooLong", err)
	}
}
