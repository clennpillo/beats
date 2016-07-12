package drda

import (
	"bytes"
	_ "fmt"
	"time"
	"strings"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/streambuf"
	"github.com/elastic/beats/libbeat/logp"
	_ "github.com/Intermernet/ebcdic"
)

// Drda message
type message struct {
	Ts    time.Time
    start int
    end   int
    ddm   Ddm
    parameters map[uint16]Parameter
    RemainingLength   int
    
    IsRequest    bool
    Direction    uint8
    TCPTuple     common.TcpTuple
    CmdlineTuple *common.CmdlineTuple
    
    //Raw          []byte
    Notes        []string
    
    //Raw Data
	Raw []byte
	
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
	if m.ddm.Length != 0 {
		logp.Err("DDM already initialized.")
	}

	if m.RemainingLength != 0 {
		logp.Err("Remaining length must be 0.")
	}
			
	m.parameters = make(map[uint16]Parameter)
	for s.parseOffset < len(s.data) {

		logp.Debug("drdadetailed", "parser round with parseState = %s and offset: %d, len of data is %d", s.parseState, s.parseOffset, len(s.data))

		switch s.parseState {
		case drdaStateStart:

			m.start = s.parseOffset
			if len(s.data[s.parseOffset:]) < 10 {
				logp.Err("Drda DDM Message too short. Ignore it.")
				return false, false
			}

			hdr := s.data[s.parseOffset : s.parseOffset+10]
			if hdr[2] != Drda_MAGIC {
				logp.Err("No Drda magic byte found (%X) but %X", Drda_MAGIC, uint8(hdr[2]))
				return false, false
			}

			ddm := &Ddm{}

			ddm.Length= uint16(hdr[0])<<8 | uint16(hdr[1])
			ddm.Format = uint8(hdr[3])
			ddm.Cor = uint16(hdr[4])<<8 | uint16(hdr[5])
			ddm.Length2 = uint16(hdr[6])<<8 | uint16(hdr[7])
			ddm.Codepoint = uint16(hdr[8])<<8 | uint16(hdr[9])
			m.ddm = *ddm

			m.end = m.start + int(ddm.Length)
			m.RemainingLength = int(ddm.Length) - 10;

			logp.Debug("drdadetailed", ">>>> Drda DDM: Length %d, codepoint %s",ddm.Length, drdaAbbrev(ddm.Codepoint))
		    s.parseOffset += 10

			codePointStr := drdaAbbrev(ddm.Codepoint)
			if(strings.EqualFold(codePointStr, "SQLSTT")){
				m.IsRequest = true
			}
			
			if(!strings.EqualFold(codePointStr, "SQLSTT") &&
		       !strings.EqualFold(codePointStr, "SQLDARD")) {
		       	s.parseOffset += m.RemainingLength
				continue;
		    }		

			if ddm.Length > 10 {
				s.parseState = drdaStateContent
				continue
			} else {
				logp.Debug("drdadetailed", "       - No parameters")
				return true, true
			}
		break

		case drdaStateContent:

		    if len(s.data[s.parseOffset:]) < 4 {
				logp.Err("Parameters message too short. Ignore it.")
				return false, false
			}

		    contentLength :=  uint16(s.data[s.parseOffset])<<8 | uint16(s.data[s.parseOffset+1])

		    if contentLength == 0 {
		    	logp.Debug("drdadetailed", "       - Parameter with zero length, thats ok possibly for data parameters")
//		    	s.parseOffset += m.RemainingLength
//				s.parseState = drdaStateContent
//				continue;
				contentLength += uint16(m.RemainingLength)
		    }

		    if contentLength == 255 {
		    	logp.Debug("drdadetailed","        - Parameter with invalid length of 255, thats ok but immediately advance to next DDM")
		    	s.parseOffset += m.RemainingLength
		    	s.parseState = drdaStateStart
				continue;
		    }

		    if int(contentLength) > m.RemainingLength {
		    	logp.Debug("drdadetailed","        - Parameter with invalid length of %d, thats not ok",int(contentLength))
		    	s.parseOffset += m.RemainingLength
		    	s.parseState = drdaStateStart
				return false, false
		    }

		    dataLength := int(contentLength) -4
		    codePoint :=  uint16(s.data[s.parseOffset+2])<<8 | uint16(s.data[s.parseOffset+3])

			parameter := &Parameter{}
			parameter.Length = contentLength
			parameter.Codepoint = codePoint

            logp.Debug("drdadetailed", "       - Parameter: Length %d %s (%s)", contentLength, drdaAbbrev(codePoint), drda_description[codePoint])
            var data []byte

			if dataLength > 0 {
				// this data parameter must be a sql I think
				sqlLen := int(s.data[s.parseOffset+4])
			    data = s.data[s.parseOffset +5: s.parseOffset+5+sqlLen]
			    parameter.ASCIIData = string(data)
//			    parameter.EBCDICData = string(ebcdic.Decode(data))
			}

			m.parameters[codePoint] = *parameter
			m.RemainingLength -= int(contentLength);
			s.parseOffset += int(contentLength);

			if m.RemainingLength <= 0 {
				s.parseOffset = len(s.data)
				return true, true
			}

	  } //end switch
	}//end for

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
