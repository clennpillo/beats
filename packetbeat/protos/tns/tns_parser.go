package tns

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/libbeat/logp"
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

	sql     common.NetString

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

	for s.parseOffset < len(s.data) {
		
//		packetLen := uint16(s.data[s.parseOffset])<<8 | uint16(s.data[s.parseOffset+1])
		
		m.start = s.parseOffset
		m.end = len(s.data)
		
		if(len(s.data)<13){
			debugf("less than 12 bytes")
			return false, false
		}
		
		dataFlag := s.data[8:10]
		if bytes.Equal(dataFlag, []byte("\x00\x40")) { // connectionn terminate
			logp.Err("connection terminate")
			return false, false
		}
		
		packetType := s.data[4:5]
		if !bytes.Equal(packetType, []byte("\x06")) {
			logp.Err("not a data packet")
			return false, false
		}
		
		// request
		
		if bytes.Equal(s.data[10:12], []byte("\x11\x69")) {
			m.IsRequest = true
			
			// get sql
			i := bytes.Index(s.data[s.parseOffset:], []byte("\x7f\xff\xff\xff"))
			if i == -1 {
				logp.Err("i value = -1")
				return false, false
			}
			i += +4
			if bytes.Equal(s.data[i:i+1], []byte("\x00")) {
				i += 9
			} else {
				i += 10
			}
			if bytes.Equal(s.data[i:i+2], []byte("\xfe\x40")) {
				i += 2
			} else {
				i += 1
			}
			
			k1 := bytes.Index(s.data[i:], []byte("\x00"))
			if i == -1 {
				logp.Err("k1 value = -1")
				return false, false
			}
			k2 := bytes.Index(s.data[i:], []byte("\x01"))
			if i == -1 {
				logp.Err("k2 value = -1")
				return false, false
			}
			var k = 0
			if k1 < k2 {
				k = k1
			} else {
				k = k2
			}
			sql := s.data[i:i+k]

			m.sql = sql
			
			return true, true
		}
		
		// select response
		if bytes.Equal(s.data[10:12], []byte("\x10\x17")) {
			return true, true
		}
		// update response
		if bytes.Equal(s.data[10:12], []byte("\x08\x01")) {
			return true, true
		}
		// insert response
		if bytes.Equal(s.data[10:12], []byte("\x0b\x05")) {
			return true, true
		}
		
		s.parseOffset = len(s.data)
		break
	}

	return false, false
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
