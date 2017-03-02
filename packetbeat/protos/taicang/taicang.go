package taicang

import (
	"bytes"
	"expvar"
	"net/url"
	"strings"
	"time"
	_ "strconv"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
)

var debugf = logp.MakeDebug("taicang")
var detailedf = logp.MakeDebug("taicangdetailed")

type parserState uint8

const (
	stateStart parserState = iota
	stateFLine
	stateHeaders
	stateBody
	stateBodyChunkedStart
	stateBodyChunked
	stateBodyChunkedWaitFinalCRLF
)

var (
	unmatchedResponses = expvar.NewInt("taicang.unmatched_responses")
)

type stream struct {
	tcptuple *common.TCPTuple

	data []byte

	parseOffset  int
	parseState   parserState
	bodyReceived int

	message *message
}

type taicangConnectionData struct {
	streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// Taicang application level protocol analyser plugin.
type taicangPlugin struct {
	// config
	ports               []int
	sendRequest         bool
	sendResponse        bool
	splitCookie         bool
	hideKeywords        []string
	redactAuthorization bool
	includeBodyFor      []string
	maxMessageSize      int

	parserConfig parserConfig

	transactionTimeout time.Duration

	results publish.Transactions
}

var (
	isDebug    = false
	isDetailed = false
)

func init() {
	protos.Register("taicang", New)
}

func New(
	testMode bool,
	results publish.Transactions, 
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &taicangPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

// Init initializes the Taicang protocol analyser.
func (taicang *taicangPlugin) init(results publish.Transactions, config *taicangConfig) error {
	taicang.setFromConfig(config)

	isDebug = logp.IsDebug("taicang")
	isDetailed = logp.IsDebug("taicangdetailed")
	taicang.results = results
	return nil
}

func (taicang *taicangPlugin) setFromConfig(config *taicangConfig) {
	taicang.ports = config.Ports
	taicang.sendRequest = config.SendRequest
	taicang.sendResponse = config.SendResponse
	taicang.hideKeywords = config.HideKeywords
	taicang.redactAuthorization = config.RedactAuthorization
	taicang.splitCookie = config.SplitCookie
	taicang.parserConfig.realIPHeader = strings.ToLower(config.RealIPHeader)
	taicang.transactionTimeout = config.TransactionTimeout
	taicang.includeBodyFor = config.IncludeBodyFor
	taicang.maxMessageSize = config.MaxMessageSize

	if config.SendAllHeaders {
		taicang.parserConfig.sendHeaders = true
		taicang.parserConfig.sendAllHeaders = true
	} else {
		if len(config.SendHeaders) > 0 {
			taicang.parserConfig.sendHeaders = true

			taicang.parserConfig.headersWhitelist = map[string]bool{}
			for _, hdr := range config.SendHeaders {
				taicang.parserConfig.headersWhitelist[strings.ToLower(hdr)] = true
			}
		}
	}
}

// GetPorts lists the port numbers the Taicang protocol analyser will handle.
func (taicang *taicangPlugin) GetPorts() []int {
	return taicang.ports
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (taicang *taicangPlugin) messageGap(s *stream, nbytes int) (ok bool, complete bool) {
	
	// assume we cannot recover
	return false, false
}

func (st *stream) PrepareForNewMessage() {
	st.data = st.data[st.message.end:]
	st.parseState = stateStart
	st.parseOffset = 0
	st.bodyReceived = 0
	st.message = nil
}

// Called when the parser has identified the boundary
// of a message.
func (taicang *taicangPlugin) messageComplete(
	conn *taicangConnectionData,
	tcptuple *common.TCPTuple,
	dir uint8,
	st *stream,
) {
	st.message.raw = st.data[st.message.start:st.message.end]

	taicang.handleTaicang(conn, st.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured Taicang transaction timeout.
func (taicang *taicangPlugin) ConnectionTimeout() time.Duration {
	return taicang.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (taicang *taicangPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseTaicang exception")

	conn := ensureTaicangConnection(private)
	conn = taicang.doParse(conn, pkt, tcptuple, dir)
	if conn == nil {
		return nil
	}
	return conn
}

func ensureTaicangConnection(private protos.ProtocolData) *taicangConnectionData {
	conn := getTaicangConnection(private)
	if conn == nil {
		conn = &taicangConnectionData{}
	}
	return conn
}

func getTaicangConnection(private protos.ProtocolData) *taicangConnectionData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*taicangConnectionData)
	if !ok {
		logp.Warn("taicang connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: taicang connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (taicang *taicangPlugin) doParse(
	conn *taicangConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
) *taicangConnectionData {

	if isDetailed {
		detailedf("Payload received: [%s]", pkt.Payload)
	}

	extraMsgSize := 0 // size of a "seen" packet for which we don't store the actual bytes

	st := conn.streams[dir]
	if st == nil {
		st = newStream(pkt, tcptuple)
		conn.streams[dir] = st
	} else {
		// concatenate bytes
		if len(st.data)+len(pkt.Payload) > taicang.maxMessageSize {
			if isDebug {
				debugf("Stream data too large, ignoring message")
			}
			extraMsgSize = len(pkt.Payload)
		} else {
			st.data = append(st.data, pkt.Payload...)
		}
	}

	for len(st.data) > 0 {
		if st.message == nil {
			st.message = &message{ts: pkt.Ts}
		}

		parser := newParser(&taicang.parserConfig)
		ok, complete := parser.parse(st, extraMsgSize)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.streams[dir] = nil
			return conn
		}

		if !complete {
			// wait for more data
			break
		}

		// all ok, ship it
		taicang.messageComplete(conn, tcptuple, dir, st)

		// and reset stream for next message
		st.PrepareForNewMessage()
	}

	return conn
}

func newStream(pkt *protos.Packet, tcptuple *common.TCPTuple) *stream {
	return &stream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &message{ts: pkt.Ts},
	}
}

// ReceivedFin will be called when TCP transaction is terminating.
func (taicang *taicangPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	debugf("Received FIN")
	conn := getTaicangConnection(private)
	if conn == nil {
		return private
	}

	stream := conn.streams[dir]
	if stream == nil {
		return conn
	}

	if stream.message != nil && len(stream.data[stream.message.start:]) > 0 {
		stream.message.raw = stream.data[stream.message.start:]
		taicang.handleTaicang(conn, stream.message, tcptuple, dir)

		// and reset message. Probably not needed, just to be sure.
		stream.PrepareForNewMessage()
	}

	return conn
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
func (taicang *taicangPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(taicang) exception")

	conn := getTaicangConnection(private)
	if conn == nil {
		return private, false
	}

	stream := conn.streams[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	ok, complete := taicang.messageGap(stream, nbytes)
	if isDetailed {
		detailedf("messageGap returned ok=%v complete=%v", ok, complete)
	}
	if !ok {
		// on errors, drop stream
		conn.streams[dir] = nil
		return conn, true
	}

	if complete {
		// Current message is complete, we need to publish from here
		taicang.messageComplete(conn, tcptuple, dir, stream)
	}

	// don't drop the stream, we can ignore the gap
	return private, false
}

func (taicang *taicangPlugin) handleTaicang(
	conn *taicangConnectionData,
	m *message,
	tcptuple *common.TCPTuple,
	dir uint8,
) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IPPort())
	taicang.hideHeaders(m)

	if m.isRequest {
		if isDebug {
			debugf("Received request with tuple: %s", m.tcpTuple)
		}
		if conn.requests.tail != nil {
			for !conn.requests.empty() {
				conn.requests.pop()
			}
		}
		conn.requests.append(m)
	} else {
		if isDebug {
			debugf("Received response with tuple: %s", m.tcpTuple)
		}
		conn.responses.append(m)
		taicang.correlate(conn)
	}
}

func (taicang *taicangPlugin) correlate(conn *taicangConnectionData) {
	// drop responses with missing requests
	if conn.requests.empty() {
		for !conn.responses.empty() {
			debugf("Response from unknown transaction. Ingoring.")
			unmatchedResponses.Add(1)
			conn.responses.pop()
		}
		return
	}

	// merge requests with responses into transactions
	for !conn.responses.empty() && !conn.requests.empty() {
		requ := conn.requests.pop()
		resp := conn.responses.pop()
		trans := taicang.newTransaction(requ, resp)

		if isDebug {
			debugf("Taicang transaction completed")
		}
		taicang.publishTransaction(trans)
	}
}

func (taicang *taicangPlugin) newTransaction(requ, resp *message) common.MapStr {
	status := common.OK_STATUS
	if resp.statusCode >= 400 {
		status = common.ERROR_STATUS
	}

	// resp_time in milliseconds
	responseTime := int32(resp.ts.Sub(requ.ts).Nanoseconds() / 1e6)

	src := common.Endpoint{
		IP:   requ.tcpTuple.SrcIP.String(),
		Port: requ.tcpTuple.SrcPort,
		Proc: string(requ.cmdlineTuple.Src),
	}
	dst := common.Endpoint{
		IP:   requ.tcpTuple.DstIP.String(),
		Port: requ.tcpTuple.DstPort,
		Proc: string(requ.cmdlineTuple.Dst),
	}
	if requ.direction == tcp.TCPDirectionReverse {
		src, dst = dst, src
	}

	event := common.MapStr{
		"@timestamp":   common.Time(requ.ts),
		"type":         "taicang",
		"status":       status,
		"responsetime": responseTime,
		"src":          &src,
		"dst":          &dst,
		"tranCode": requ.cbodData["tranCode"],
		"mfTranCode": requ.cbodData["mfTranCode"],
		"retCode": resp.cbodData["retCode"],

	}

	return event
}

func (taicang *taicangPlugin) publishTransaction(event common.MapStr) {
	if taicang.results == nil {
		return
	}
	taicang.results.PublishTransaction(event)
}

func (taicang *taicangPlugin) RemovalListener(data protos.ProtocolData) {
	if conn, ok := data.(*taicangConnectionData); ok {
		if !conn.requests.empty() && conn.responses.empty() {
			requ := conn.requests.pop()
			resp := &message{
				statusCode: 700,
			}
			result := taicang.newTransaction(requ, resp)
			taicang.results.PublishTransaction(result)
		}
	} else {
		logp.Warn("Not a taicangConnectionData")
	}
}

func (taicang *taicangPlugin) collectHeaders(m *message) interface{} {

	hdrs := map[string]interface{}{}

	hdrs["content-length"] = m.contentLength
	if len(m.contentType) > 0 {
		hdrs["content-type"] = m.contentType
	}

	if taicang.parserConfig.sendHeaders {

		cookie := "cookie"
		if !m.isRequest {
			cookie = "set-cookie"
		}

		for name, value := range m.headers {
			if strings.ToLower(name) == "content-type" {
				continue
			}
			if strings.ToLower(name) == "content-length" {
				continue
			}
			if taicang.splitCookie && name == cookie {
				hdrs[name] = splitCookiesHeader(string(value))
			} else {
				hdrs[name] = value
			}
		}
	}
	return hdrs
}

func (taicang *taicangPlugin) setBody(result common.MapStr, m *message) {
	body := string(taicang.extractBody(m))
	if len(body) > 0 {
		result["body"] = body
	}
}

func splitCookiesHeader(headerVal string) map[string]string {
	cookies := map[string]string{}

	cstring := strings.Split(headerVal, ";")
	for _, cval := range cstring {
		cookie := strings.SplitN(cval, "=", 2)
		if len(cookie) == 2 {
			cookies[strings.ToLower(strings.TrimSpace(cookie[0]))] =
				parseCookieValue(strings.TrimSpace(cookie[1]))
		}
	}

	return cookies
}

func parseCookieValue(raw string) string {
	// Strip the quotes, if present.
	if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	return raw
}

func (taicang *taicangPlugin) extractBody(m *message) []byte {
	body := []byte{}

	if len(m.contentType) > 0 && taicang.shouldIncludeInBody(m.contentType) {
		if len(m.chunkedBody) > 0 {
			body = append(body, m.chunkedBody...)
		} else {
			if isDebug {
				debugf("Body to include: [%s]", m.raw[m.bodyOffset:])
			}
			body = append(body, m.raw[m.bodyOffset:]...)
		}
	}

	return body
}

func (taicang *taicangPlugin) cutMessageBody(m *message) []byte {
	cutMsg := []byte{}

	// add headers always
	cutMsg = m.raw[:m.bodyOffset]

	// add body
	return append(cutMsg, taicang.extractBody(m)...)

}

func (taicang *taicangPlugin) shouldIncludeInBody(contenttype []byte) bool {
	includedBodies := taicang.includeBodyFor
	for _, include := range includedBodies {
		if bytes.Contains(contenttype, []byte(include)) {
			if isDebug {
				debugf("Should Include Body = true Content-Type %s include_body %s",
					contenttype, include)
			}
			return true
		}
		if isDebug {
			debugf("Should Include Body = false Content-Type %s include_body %s",
				contenttype, include)
		}
	}
	return false
}

func (taicang *taicangPlugin) hideHeaders(m *message) {
	if !m.isRequest || !taicang.redactAuthorization {
		return
	}

	msg := m.raw

	// byte64 != encryption, so obscure it in headers in case of Basic Authentication

	redactHeaders := []string{"authorization", "proxy-authorization"}
	authText := []byte("uthorization:") // [aA] case insensitive, also catches Proxy-Authorization:

	authHeaderStartX := m.headerOffset
	authHeaderEndX := m.bodyOffset

	for authHeaderStartX < m.bodyOffset {
		if isDebug {
			debugf("looking for authorization from %d to %d",
				authHeaderStartX, authHeaderEndX)
		}

		startOfHeader := bytes.Index(msg[authHeaderStartX:m.bodyOffset], authText)
		if startOfHeader >= 0 {
			authHeaderStartX = authHeaderStartX + startOfHeader

			endOfHeader := bytes.Index(msg[authHeaderStartX:m.bodyOffset], []byte("\r\n"))
			if endOfHeader >= 0 {
				authHeaderEndX = authHeaderStartX + endOfHeader

				if authHeaderEndX > m.bodyOffset {
					authHeaderEndX = m.bodyOffset
				}

				if isDebug {
					debugf("Redact authorization from %d to %d", authHeaderStartX, authHeaderEndX)
				}

				for i := authHeaderStartX + len(authText); i < authHeaderEndX; i++ {
					msg[i] = byte('*')
				}
			}
		}
		authHeaderStartX = authHeaderEndX + len("\r\n")
		authHeaderEndX = m.bodyOffset
	}

	for _, header := range redactHeaders {
		if len(m.headers[header]) > 0 {
			m.headers[header] = []byte("*")
		}
	}

	m.raw = msg
}

func (taicang *taicangPlugin) hideSecrets(values url.Values) url.Values {
	params := url.Values{}
	for key, array := range values {
		for _, value := range array {
			if taicang.isSecretParameter(key) {
				params.Add(key, "xxxxx")
			} else {
				params.Add(key, value)
			}
		}
	}
	return params
}

// extractParameters parses the URL and the form parameters and replaces the secrets
// with the string xxxxx. The parameters containing secrets are defined in taicang.Hide_secrets.
// Returns the Request URI path and the (adjusted) parameters.
func (taicang *taicangPlugin) extractParameters(m *message, msg []byte) (path string, params string, err error) {
	var values url.Values

	u, err := url.Parse(string(m.requestURI))
	if err != nil {
		return
	}
	values = u.Query()
	path = u.Path

	paramsMap := taicang.hideSecrets(values)

	if m.contentLength > 0 && bytes.Contains(m.contentType, []byte("urlencoded")) {

		values, err = url.ParseQuery(string(msg[m.bodyOffset:]))
		if err != nil {
			return
		}

		for key, value := range taicang.hideSecrets(values) {
			paramsMap[key] = value
		}
	}

	params = paramsMap.Encode()
	if isDetailed {
		detailedf("Form parameters: %s", params)
	}
	return
}

func (taicang *taicangPlugin) isSecretParameter(key string) bool {
	for _, keyword := range taicang.hideKeywords {
		if strings.ToLower(key) == keyword {
			return true
		}
	}
	return false
}

func (ml *messageList) append(msg *message) {
	if ml.tail == nil {
		ml.head = msg
	} else {
		ml.tail.next = msg
	}
	msg.next = nil
	ml.tail = msg
}

func (ml *messageList) empty() bool {
	return ml.head == nil
}

func (ml *messageList) pop() *message {
	if ml.head == nil {
		return nil
	}

	msg := ml.head
	ml.head = ml.head.next
	if ml.head == nil {
		ml.tail = nil
	}
	return msg
}

func (ml *messageList) last() *message {
	return ml.tail
}
