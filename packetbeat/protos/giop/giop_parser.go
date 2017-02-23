package giop

import (
	"bytes"
	_ "errors"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	_ "github.com/elastic/beats/libbeat/logp"
)

// Http Message
type message struct {
	Ts               time.Time
	hasContentLength bool
	headerOffset     int
	bodyOffset       int
	version          version
	connection       common.NetString
	chunkedLength    int
	chunkedBody      []byte

	IsRequest    bool
	TCPTuple     common.TcpTuple
	CmdlineTuple *common.CmdlineTuple
	Direction    uint8

	//Request Info
	RequestURI   common.NetString
	Method       common.NetString
	StatusCode   uint16
	StatusPhrase common.NetString
	RealIP       common.NetString

	// Http Headers
	ContentLength    int
	ContentType      common.NetString
	TransferEncoding common.NetString
	Headers          map[string]common.NetString
	Size             uint64

	//Raw Data
	Raw []byte

	Notes []string

	//Timing
	start int
	end   int

	next *message
}

type version struct {
	major uint8
	minor uint8
}

type parser struct {
	config *parserConfig
}

type parserConfig struct {
	RealIPHeader     string
	SendHeaders      bool
	SendAllHeaders   bool
	HeadersWhitelist map[string]bool
}

var (
	transferEncodingChunked = []byte("chunked")

	constCRLF = []byte("\r\n")

	constClose     = []byte("close")
	constKeepAlive = []byte("keep-alive")

	nameContentLength    = []byte("content-length")
	nameContentType      = []byte("content-type")
	nameTransferEncoding = []byte("transfer-encoding")
	nameConnection       = []byte("connection")
)

func newParser(config *parserConfig) *parser {
	return &parser{config: config}
}

func (parser *parser) parse(s *stream) (bool, bool) {
	m := s.message

	if cont, ok, complete := parser.parseGiopSign(s, m); !cont {
		return ok, complete
	}

	return true, false
}

func (*parser) parseGiopSign(s *stream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset
	
	if bytes.Equal(s.data[0:8], []byte("GIOP\x01\x02\x00\x01")) {
		//RESPONSE
		m.IsRequest = false

		if isDebug {
			debugf("Giop response found")
		}

		s.parseOffset += len(s.data)	
		m.end = s.parseOffset	
		return false, true, true
	} else if bytes.Equal(s.data[0:8], []byte("GIOP\x01\x02\x00\x00")) {
		// REQUEST
		m.IsRequest = true
		
		if isDebug {
			debugf("Giop request found")
		}
		
		s.parseOffset += len(s.data)
		m.end = s.parseOffset
		return false, true, true
	}
	
	if isDebug {
		debugf("Couldn't understand Giop message: %s", s.data[0:8])
	}

	// ok so far
//	s.parseOffset = len(s.data)
	//m.headerOffset = s.parseOffset
	//s.parseState = stateHeaders

	return false, false, false
}

func trim(buf []byte) []byte {
	return trimLeft(trimRight(buf))
}

func trimLeft(buf []byte) []byte {
	for i, b := range buf {
		if b != ' ' && b != '\t' {
			return buf[i:]
		}
	}
	return nil
}

func trimRight(buf []byte) []byte {
	for i := len(buf) - 1; i > 0; i-- {
		b := buf[i]
		if b != ' ' && b != '\t' {
			return buf[:i+1]
		}
	}
	return nil
}

func parseInt(line []byte) (int, error) {
	buf := streambuf.NewFixed(line)
	i, err := buf.AsciiInt(false)
	return int(i), err
	// TODO: is it an error if 'buf.Len() != 0 {}' ?
}

func toLower(buf, in []byte) []byte {
	if len(in) > len(buf) {
		goto unbufferedToLower
	}

	for i, b := range in {
		if b > 127 {
			goto unbufferedToLower
		}

		if 'A' <= b && b <= 'Z' {
			b = b - 'A' + 'a'
		}
		buf[i] = b
	}
	return buf[:len(in)]

unbufferedToLower:
	return bytes.ToLower(in)
}
