package gofakes3

import (
	"bufio"
	"errors"
	"io"
)

// isStreamingPayload reports whether the X-Amz-Content-Sha256 value announces
// an aws-chunked body. Newer SDKs/CLIs (default checksum behaviour) send the
// -TRAILER variants, which append a checksum trailer after the final chunk.
func isStreamingPayload(sha string) bool {
	switch sha {
	case "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER":
		return true
	}
	return false
}

var errChunkHeader = errors.New("expected integer")

// chunkedReader decodes an aws-chunked body:
//
//	hex-size[;chunk-signature=...]\r\n data \r\n ... 0[;chunk-signature=...]\r\n
//	[trailer-name:value\r\n]* \r\n
//
// Signatures and trailers are consumed but not verified.
type chunkedReader struct {
	inner       *bufio.Reader
	chunkRemain int
	started     bool
	done        bool
}

func newChunkedReader(inner io.Reader) *chunkedReader {
	return &chunkedReader{inner: bufio.NewReader(inner)}
}

func (r *chunkedReader) Read(p []byte) (n int, err error) {
	for n < len(p) {
		if r.done {
			return n, io.EOF
		}
		if r.chunkRemain > 0 {
			sizeToRead := len(p) - n
			if sizeToRead > r.chunkRemain {
				sizeToRead = r.chunkRemain
			}
			innerN, err := r.inner.Read(p[n : n+sizeToRead])
			r.chunkRemain -= innerN
			n += innerN
			if err != nil {
				return n, err
			}
			continue
		}

		if r.started {
			// skip the CRLF that terminates the previous chunk's data
			if _, err := r.inner.Discard(2); err != nil {
				return n, err
			}
		}
		r.started = true

		size, err := r.readChunkHeader()
		if err != nil {
			return n, err
		}
		if size == 0 {
			if err := r.skipTrailers(); err != nil {
				return n, err
			}
			r.done = true
			return n, io.EOF
		}
		r.chunkRemain = size
	}
	return n, nil
}

// readChunkHeader reads "hex-size[;extensions]\r\n" and returns the size.
func (r *chunkedReader) readChunkHeader() (int, error) {
	var size, digits int = 0, 0

	for {
		b, err := r.inner.ReadByte()
		if err != nil {
			return 0, err
		}
		var v int
		switch {
		case b >= '0' && b <= '9':
			v = int(b - '0')
		case b >= 'a' && b <= 'f':
			v = int(b-'a') + 10
		case b >= 'A' && b <= 'F':
			v = int(b-'A') + 10
		case digits > 0 && (b == ';' || b == '\r'):
			// skip chunk-signature or other extensions up to the newline
			if b == '\r' {
				if err := r.inner.UnreadByte(); err != nil {
					return 0, err
				}
			}

			// skip the rest of the line (extensions) and the CRLF that terminates the chunk header
			if _, err := r.inner.ReadString('\n'); err != nil {
				return 0, err
			}
			return size, nil
		default:
			return 0, errChunkHeader
		}
		size = size<<4 | v
		digits++
		if digits > 8 {
			return 0, errChunkHeader
		}
	}
}

// skipTrailers consumes optional trailing headers (e.g.
// x-amz-checksum-crc32, x-amz-trailer-signature) up to the blank line.
func (r *chunkedReader) skipTrailers() error {
	for {
		line, err := r.inner.ReadString('\n')
		if len(line) <= 2 { // "\r\n", "\n" or empty
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
