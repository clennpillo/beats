package mq

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	_"github.com/elastic/beats/packetbeat/protos/lib"
	_"encoding/binary"
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
	
	MqType string
	
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

	if cont, ok, complete := parser.parseMqSign(s, m); !cont {
		return ok, complete
	}

	return true, false
}

func (*parser) parseMqSign(s *stream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset
	debugf("1")
	if !bytes.Equal(s.data[0:3], []byte("\x54\x53\x48")){
		debugf("2")
		return false, false, false
	}
	debugf("3")
	if bytes.Equal(s.data[9:10], []byte("\x96")) || //MQPUT_REPLY
	   bytes.Equal(s.data[9:10], []byte("\x95")) {  //MQGET_REPLY
	   
	    //RESPONSE
		m.IsRequest = false
		
		debugf("reponse")
		
	    if bytes.Equal(s.data[9:10], []byte("\x96")) {
	    	m.MqType = "MQPUT_REPLY"
	    }else{
	    	m.MqType = "MQGET_REPLY"
	    	debugf("MQGET_REPLY")
	    	
	    	// the packet is not complete
//	    	debugf("len data is : %d", len(s.data))
//	    	if(len(s.data)<512){
//	    		debugf("too short")
//	    		return false, true, false
//	    	}else{
//	    		// 508-512 is mq data length
//	    		len_data := int32(binary.BigEndian.Uint32(s.data[508:512]))
//	    		debugf("data length is: %d", len_data)
//	    		if(int32(len(s.data))<(int32(512)+len_data)){
//	    			debugf("still too small")
//	    			return false, true, false 
//	    		}
//	    	}
//	    	m.cbodData = lib.ParseCBODOut(s.data[512:len(s.data)])
	    }

		if isDebug {
			debugf("Mq response found")
		}

		s.parseOffset += len(s.data)	
		m.end = s.parseOffset
		debugf("41")	
		return false, true, true
	} else if bytes.Equal(s.data[9:10], []byte("\x86")) || //MQPUT
	          bytes.Equal(s.data[9:10], []byte("\x85")){   //MQGET
	          	
		// REQUEST
		m.IsRequest = true
		
		debugf("req")
		
		if bytes.Equal(s.data[9:10], []byte("\x86")) {
	    	m.MqType = "MQPUT"
	    	debugf("MQPUT")
	    	
	    	debugf("len is %d", len(s.data))
	    	debugf("packet data : [%s]", s.data)
	    	
	    	// the packet is not complete
//	    	if(len(s.data)<540){
//	    		debugf("too short")
//	    		return false, true, false
//	    	}else{
//	    		// 536-540 is mq data length
//	    		len_data := int32(binary.BigEndian.Uint32(s.data[536:540]))
//	    		debugf("data length is: %d", len_data)
//	    		if(int32(len(s.data))<(int32(512)+len_data)){
//	    			debugf("still too small")
//	    			return false, true, false 
//	    		}
//	    	}
//	    	m.cbodData = lib.ParseCBODIn(s.data[540:len(s.data)])
	    }else{
	    	m.MqType = "MQGET"
	    }
	    
	    m.msgId = string(bytes.Trim(s.data[92:116],"\x00"))
		m.correlId = string(bytes.Trim(s.data[116:140],"\x00"))
		
		if isDebug {
			debugf("Mq request found")
		}
		
		s.parseOffset += len(s.data)
		m.end = s.parseOffset
		debugf("42")
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
