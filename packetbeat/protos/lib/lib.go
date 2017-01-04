package lib

import (
	"github.com/Intermernet/ebcdic"
)



func ParseCBODIn(cbodBytes []byte) map[string]interface{} {
	
	event := map[string]interface{}{
		"sysCode":   string(ebcdic.Decode(cbodBytes[100:104])),
		"busCode":   string(ebcdic.Decode(cbodBytes[104:108])),
	}
	
	return event
}

func ParseCBODOut(cbodBytes []byte) map[string]interface{} {
	
	event := map[string]interface{}{
		"test":   "good",
	}
	
	return event
}
