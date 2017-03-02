package afa2

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	"encoding/binary"
)

// afa2 Message
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

	// afa2 Headers
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
	
	tranCode		string
	templateCode	string
	retCode			string
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

	if cont, ok, complete := parser.parseAfa2Sign(s, m); !cont {
		return ok, complete
	}

	return true, false
}

func (*parser) parseAfa2Sign(s *stream, m *message) (cont, ok, complete bool) {
	m.start = s.parseOffset
	
		if(len(s.data)<10){
		debugf("too short, bad data")
		return false, false, false
	}

	if !bytes.Equal(s.data[4:10], []byte("\x01\x00\x00\x00\x00\x01")){
		return false, false, false
	}
	
    debugf("actual payload length is %d", len(s.data))
	len_data := int32(binary.BigEndian.Uint32(s.data[0:4]))
	debugf("data length should be : %d", len_data+4)
	if(int32(len(s.data))<(int32(4)+len_data)){
		debugf("still too small")
		return false, true, false 
	}
	debugf("message joined complete")
	
	if bytes.Equal(s.data[29:31], []byte("\x00\x00")) &&
	   bytes.Equal(s.data[49:51], []byte("\x00\x00")) &&
	   bytes.Equal(s.data[69:71], []byte("\x00\x00")) {
	   	
	   	m.isRequest = true
		if isDebug {
			debugf("afa2 request found")
		}
		
		m.tranCode = string(bytes.Trim(s.data[11:31],"\x00"))
		m.templateCode = string(bytes.Trim(s.data[31:51],"\x00"))
		
		s.parseOffset += len(s.data)	
		m.end = s.parseOffset
		return false, true, true
		
	}else if bytes.Equal(s.data[29:31], []byte("\x20\x20")) &&
	         bytes.Equal(s.data[49:51], []byte("\x20\x20")) &&
	         bytes.Equal(s.data[69:71], []byte("\x20\x20")) {
		m.isRequest = false
		if isDebug {
			debugf("afa2 response found")
		}
		
		retSign := "thirdsyserrcode"
		retCodeIndex := bytes.Index(s.data, []byte(retSign))
		if retCodeIndex == -1 {
			retSign = "errnum"
			retCodeIndex = bytes.Index(s.data, []byte(retSign))
		}
		if retCodeIndex == -1 {
			retSign = "errorCode"
			retCodeIndex = bytes.Index(s.data, []byte(retSign))
		}
		if retCodeIndex != -1{
			debugf("%s index is : %d", retSign, retCodeIndex)
			lenSign := len(retSign)
			debugf("len of sign is : %d", lenSign)
			len_errorCode := int(binary.BigEndian.Uint16(s.data[retCodeIndex+lenSign:retCodeIndex+lenSign+2]))
			debugf("%s len is : %d", retSign, len_errorCode)
			m.retCode = string(s.data[retCodeIndex+lenSign+2:retCodeIndex+lenSign+2+len_errorCode])
			
			debugf("%s is : %s", retSign, m.retCode)
		}
		
		s.parseOffset += len(s.data)	
		m.end = s.parseOffset
		return false, true, true
	}

	if bytes.Equal(s.data[71:72], []byte("\x11")){  // cardchk afe req
	}
	
	if bytes.Equal(s.data[76:84], []byte("\x4e\x6f\x6e\x65\x03\x50\x43\x4b")){  // None.PCK
	}

	if bytes.Equal(s.data[71:72], []byte("\x0d")){  // afa2 afe response
//		tranType = string(s.data[72:89])
//
//		m.IsRequest = false
//    	
//	    //m.cbodData = lib.ParseCBODIn(s.data[107:len(s.data)])
//
//		if isDebug {
//			debugf("afa2 response found")
//		}
//
//		return false, true, true
	}

	if bytes.Equal(s.data[71:72], []byte("\x03")){  // PCK

//		m.IsRequest = true
//		
//	    //m.cbodData = lib.ParseCBODOut(s.data[62:len(s.data)])
//	    
//		if isDebug {
//			debugf("afa2 request found")
//		}
//		
//		s.parseOffset += len(s.data)
//		m.end = s.parseOffset
//
//		return false, true, true
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