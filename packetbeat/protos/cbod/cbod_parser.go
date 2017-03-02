package cbod

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/packetbeat/protos/lib"
	"github.com/elastic/beats/libbeat/common/streambuf"
	"encoding/binary"
)

// Cbod Message
type message struct {
	ts               time.Time
	hasContentLength bool
	headerOffset     int
	version          version
	connection       common.NetString
	chunkedLength    int
	chunkedBody      []byte

	isRequest    bool
	tcpTuple     common.TCPTuple
	cmdlineTuple *common.CmdlineTuple
	direction    uint8

	//Request Info
	requestURI   common.NetString
	method       common.NetString
	statusCode   uint16
	statusPhrase common.NetString
	realIP       common.NetString

	// Cbod Headers
	contentLength    int
	contentType      common.NetString
	transferEncoding common.NetString
	headers          map[string]common.NetString
	size             uint64

	//Raw Data
	raw []byte

	notes []string

	//Offsets
	start      int
	end        int
	bodyOffset int

	next *message
	
	cbodData map[string]interface{}

}

type version struct {
	major uint8
	minor uint8
}

type parser struct {
	config *parserConfig
}

type parserConfig struct {
	realIPHeader     string
	sendHeaders      bool
	sendAllHeaders   bool
	headersWhitelist map[string]bool
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

func (parser *parser) parse(s *stream, extraMsgSize int) (bool, bool) {
	m := s.message

//	if extraMsgSize > 0 {
//		// A packet of extraMsgSize size was seen, but we don't have
//		// its actual bytes. This is only usable in the `stateBody` state.
//		if s.parseState != stateBody {
//			return false, false
//		}
//		return parser.eatBody(s, m, extraMsgSize)
//	}

	if cont, ok, complete := parser.parseCbodSign(s, m); !cont {
		return ok, complete
	}

	return true, false
}

func (*parser) parseCbodSign(s *stream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset
	
	debugf("len data is : %d", len(s.data))
	if(len(s.data)<4){
		debugf("too short")
		return false, false, false
	}else{
		len_data := int32(binary.BigEndian.Uint32(s.data[0:4]))
		debugf("data length is: %d", len_data)
		if(int32(len(s.data))<len_data){
			debugf("still too small")
			return false, true, false 
		}
	}

	if bytes.Equal(s.data[22:24], []byte("\xe3\xc3")) && //TC
	   bytes.Equal(s.data[92:94], []byte("\xe3\xc3")){   //TC
		//REQUEST
		m.isRequest = true
    	
	    m.cbodData = lib.ParseCBODIn(s.data[104:len(s.data)])

		if isDebug {
			debugf("Cbod request found")
		}

		s.parseOffset += len(s.data)	
		m.end = s.parseOffset
		return false, true, true
	}
	
	if bytes.Equal(s.data[4:6], []byte("\x00\x00")) &&
	   bytes.Equal(s.data[8:12], []byte("\x00\x03\x00\x01")){
	          	
		// RESPONSE
		m.isRequest = false
		
	    m.cbodData = lib.ParseCBODOut(s.data[31:len(s.data)])
	    
		if isDebug {
			debugf("Cbod response found")
		}
		
		s.parseOffset += len(s.data)
		m.end = s.parseOffset

		return false, true, true
	}


	// ok so far
	s.parseOffset = m.end
	m.headerOffset = s.parseOffset
	s.parseState = stateHeaders

	return true, true, true
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
	i, err := buf.IntASCII(false)
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