package ctg

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/packetbeat/protos/lib"
	"encoding/binary"
)

// Ctg Message
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
	
	CtgType string
	
	msgId string
	correlId string
	
	cbodData map[string]interface{}

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

	if cont, ok, complete := parser.parseCtgSign(s, m); !cont {
		return ok, complete
	}

	return true, false
}

func (*parser) parseCtgSign(s *stream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset

	if !bytes.Equal(s.data[0:6], []byte("\x47\x61\x74\x65\x00\x50")){
		return false, false, false
	}
	
	if(len(s.data)<32){
		debugf("too short, bad data")
		return false, false, false
	}else{
		// 28-32 is ctg data length
		len_data := int32(binary.BigEndian.Uint32(s.data[28:32]))
		debugf("data length is: %d", len_data)
		if(int32(len(s.data))<(int32(32)+len_data)){
			debugf("still too small")
			return false, true, false 
		}
	}

	if bytes.Equal(s.data[11:12], []byte("\x01")){
	   
	    //REQUEST
		m.IsRequest = true
    	
	    m.cbodData = lib.ParseCBODIn(s.data[107:len(s.data)])

		if isDebug {
			debugf("Ctg request found")
		}

		s.parseOffset += len(s.data)	
		m.end = s.parseOffset
		return false, true, true
	}
	
	if bytes.Equal(s.data[11:12], []byte("\x03")){
	          	
		// RESPONSE
		m.IsRequest = false
		
	    m.cbodData = lib.ParseCBODOut(s.data[62:len(s.data)])
	    
		if isDebug {
			debugf("Ctg response found")
		}
		
		s.parseOffset += len(s.data)
		m.end = s.parseOffset

		return false, true, true
	}

	// ok so far
//	s.parseOffset = len(s.data)
	//m.headerOffset = s.parseOffset
	//s.parseState = stateHeaders

	return false, false, false
}

func isVersion(v version, major, minor uint8) bool {
	return v.major == major && v.minor == minor
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
