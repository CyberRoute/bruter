package fuzzer

import (
	"bufio"
	"io"
	"os"
)

func Reader(filename string, noff int64) (chan string, int64, error) {
	fp, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}

	// if offset defined then start from there
	if noff > 0 {
		// and go to the start of the line
		b := make([]byte, 1)
		for b[0] != '\n' {
			noff--
			if _, err := fp.Seek(noff, io.SeekStart); err != nil {
				fp.Close()
				return nil, 0, err
			}
			if _, err := fp.Read(b); err != nil {
				fp.Close()
				return nil, 0, err
			}
		}
		noff++
	}

	out := make(chan string)
	go func() {
		defer fp.Close()
		defer close(out)
		scanner := bufio.NewScanner(fp)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			if _, err := fp.Seek(0, io.SeekCurrent); err != nil {
				return // Stop reading and return if seeking fails
			}
			out <- scanner.Text()
			noff += int64(len(scanner.Bytes()) + 1) // Update noff
		}
	}()

	return out, noff, nil
}
