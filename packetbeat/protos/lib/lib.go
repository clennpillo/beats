package lib

import (
	"github.com/Intermernet/ebcdic"
	"encoding/xml"
	"github.com/elastic/beats/libbeat/logp"
)

type XMLRequest struct {
	ServiceHeader	ServiceHeaderIn		`xml:"Service_Header"`
}

type ServiceHeaderIn struct {
	ServiceID		string				`xml:"service_id"`
}

type XMLResponse struct {
	ServiceHeader	ServiceHeaderOut	`xml:"Service_Header"`
}

type ServiceHeaderOut struct {
	ServiceResponse	ServiceResponse		`xml:"service_response"`
}

type ServiceResponse struct {
	Status 			string				`xml:"status"`
}

func ParseCBODIn(cbodBytes []byte) map[string]interface{} {
	
	event := map[string]interface{}{
        "tranCode":   string(ebcdic.Decode(cbodBytes[4:9])),
        "mfTranCode":  string(ebcdic.Decode(cbodBytes[29:35])),
	}
	
	return event
}
func ParseCBODOut(cbodBytes []byte) map[string]interface{} {
	
	event := map[string]interface{}{
		"retCode":   string(ebcdic.Decode(cbodBytes[11:12])),
	}
	
	return event
}

func ParseXMLIn(cbodBytes []byte) map[string]interface{} {
	var request XMLRequest
	err := xml.Unmarshal(cbodBytes, &request)
	if err != nil {
		logp.Warn("error during parsing xml")
	}

	event := map[string]interface{}{
        "tranCode":  request.ServiceHeader.ServiceID,
	}
	
	return event
}
func ParseXMLOut(cbodBytes []byte) map[string]interface{} {
	var response XMLResponse
	err := xml.Unmarshal(cbodBytes, &response)
	if err != nil {
		logp.Warn("error during parsing xml")
	}

	event := map[string]interface{}{
		"retCode":   response.ServiceHeader.ServiceResponse.Status,
	}
	
	return event
}
