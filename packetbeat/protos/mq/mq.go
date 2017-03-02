package mq

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

var debugf = logp.MakeDebug("mq")
var detailedf = logp.MakeDebug("mqdetailed")

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
	unmatchedResponses = expvar.NewInt("mq.unmatched_responses")
)

type stream struct {
	tcptuple *common.TCPTuple

	data []byte

	parseOffset  int
	parseState   parserState
	bodyReceived int

	message *message
}

type mqConnectionData struct {
	streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// Mq application level protocol analyser plugin.
type mqPlugin struct {
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
	protos.Register("mq", New)
}

func New(
	testMode bool,
	results publish.Transactions, 
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &mqPlugin{}
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

// Init initializes the Mq protocol analyser.
func (mq *mqPlugin) init(results publish.Transactions, config *mqConfig) error {
	mq.setFromConfig(config)

	isDebug = logp.IsDebug("mq")
	isDetailed = logp.IsDebug("mqdetailed")
	mq.results = results
	return nil
}

func (mq *mqPlugin) setFromConfig(config *mqConfig) {
	mq.ports = config.Ports
	mq.sendRequest = config.SendRequest
	mq.sendResponse = config.SendResponse
	mq.hideKeywords = config.HideKeywords
	mq.redactAuthorization = config.RedactAuthorization
	mq.splitCookie = config.SplitCookie
	mq.parserConfig.realIPHeader = strings.ToLower(config.RealIPHeader)
	mq.transactionTimeout = config.TransactionTimeout
	mq.includeBodyFor = config.IncludeBodyFor
	mq.maxMessageSize = config.MaxMessageSize

	if config.SendAllHeaders {
		mq.parserConfig.sendHeaders = true
		mq.parserConfig.sendAllHeaders = true
	} else {
		if len(config.SendHeaders) > 0 {
			mq.parserConfig.sendHeaders = true

			mq.parserConfig.headersWhitelist = map[string]bool{}
			for _, hdr := range config.SendHeaders {
				mq.parserConfig.headersWhitelist[strings.ToLower(hdr)] = true
			}
		}
	}
}

// GetPorts lists the port numbers the Mq protocol analyser will handle.
func (mq *mqPlugin) GetPorts() []int {
	return mq.ports
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (mq *mqPlugin) messageGap(s *stream, nbytes int) (ok bool, complete bool) {
	
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
func (mq *mqPlugin) messageComplete(
	conn *mqConnectionData,
	tcptuple *common.TCPTuple,
	dir uint8,
	st *stream,
) {
	st.message.raw = st.data[st.message.start:st.message.end]

	mq.handleMq(conn, st.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured Mq transaction timeout.
func (mq *mqPlugin) ConnectionTimeout() time.Duration {
	return mq.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (mq *mqPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseMq exception")

	conn := ensureMqConnection(private)
	conn = mq.doParse(conn, pkt, tcptuple, dir)
	if conn == nil {
		return nil
	}
	return conn
}

func ensureMqConnection(private protos.ProtocolData) *mqConnectionData {
	conn := getMqConnection(private)
	if conn == nil {
		conn = &mqConnectionData{}
	}
	return conn
}

func getMqConnection(private protos.ProtocolData) *mqConnectionData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*mqConnectionData)
	if !ok {
		logp.Warn("mq connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: mq connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (mq *mqPlugin) doParse(
	conn *mqConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
) *mqConnectionData {

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
		if len(st.data)+len(pkt.Payload) > mq.maxMessageSize {
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

		parser := newParser(&mq.parserConfig)
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
		mq.messageComplete(conn, tcptuple, dir, st)

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
func (mq *mqPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	debugf("Received FIN")
	conn := getMqConnection(private)
	if conn == nil {
		return private
	}

	stream := conn.streams[dir]
	if stream == nil {
		return conn
	}

	if stream.message != nil && len(stream.data[stream.message.start:]) > 0 {
		stream.message.raw = stream.data[stream.message.start:]
		mq.handleMq(conn, stream.message, tcptuple, dir)

		// and reset message. Probably not needed, just to be sure.
		stream.PrepareForNewMessage()
	}

	return conn
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
func (mq *mqPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(mq) exception")

	conn := getMqConnection(private)
	if conn == nil {
		return private, false
	}

	stream := conn.streams[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	ok, complete := mq.messageGap(stream, nbytes)
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
		mq.messageComplete(conn, tcptuple, dir, stream)
	}

	// don't drop the stream, we can ignore the gap
	return private, false
}

func (mq *mqPlugin) handleMq(
	conn *mqConnectionData,
	m *message,
	tcptuple *common.TCPTuple,
	dir uint8,
) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IPPort())
	mq.hideHeaders(m)

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
		mq.correlate(conn)
	}
}

func (mq *mqPlugin) correlate(conn *mqConnectionData) {
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
		trans := mq.newTransaction(requ, resp)

		if isDebug {
			debugf("Mq transaction completed")
		}
		mq.publishTransaction(trans)
	}
}

func (mq *mqPlugin) newTransaction(requ, resp *message) common.MapStr {
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
		"type":         "mq",
		"status":       status,
		"responsetime": responseTime,
		"src":          &src,
		"dst":          &dst,
		"mqtype":		resp.MqType,
		"tranCode": requ.cbodData["tranCode"],
		"mfTranCode": requ.cbodData["mfTranCode"],
		"retCode": resp.cbodData["retCode"],
		"msgId": resp.msgId,
		"correlId": resp.correlId,

	}

	return event
}

func (mq *mqPlugin) publishTransaction(event common.MapStr) {
	if mq.results == nil {
		return
	}
	mq.results.PublishTransaction(event)
}

func (mq *mqPlugin) RemovalListener(data protos.ProtocolData) {
	if conn, ok := data.(*mqConnectionData); ok {
		if !conn.requests.empty() && conn.responses.empty() {
			requ := conn.requests.pop()
			resp := &message{
				statusCode: 700,
			}
			result := mq.newTransaction(requ, resp)
			mq.results.PublishTransaction(result)
		}
	} else {
		logp.Warn("Not a mqConnectionData")
	}
}

func (mq *mqPlugin) collectHeaders(m *message) interface{} {

	hdrs := map[string]interface{}{}

	hdrs["content-length"] = m.contentLength
	if len(m.contentType) > 0 {
		hdrs["content-type"] = m.contentType
	}

	if mq.parserConfig.sendHeaders {

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
			if mq.splitCookie && name == cookie {
				hdrs[name] = splitCookiesHeader(string(value))
			} else {
				hdrs[name] = value
			}
		}
	}
	return hdrs
}

func (mq *mqPlugin) setBody(result common.MapStr, m *message) {
	body := string(mq.extractBody(m))
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

func (mq *mqPlugin) extractBody(m *message) []byte {
	body := []byte{}

	if len(m.contentType) > 0 && mq.shouldIncludeInBody(m.contentType) {
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

func (mq *mqPlugin) cutMessageBody(m *message) []byte {
	cutMsg := []byte{}

	// add headers always
	cutMsg = m.raw[:m.bodyOffset]

	// add body
	return append(cutMsg, mq.extractBody(m)...)

}

func (mq *mqPlugin) shouldIncludeInBody(contenttype []byte) bool {
	includedBodies := mq.includeBodyFor
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

func (mq *mqPlugin) hideHeaders(m *message) {
	if !m.isRequest || !mq.redactAuthorization {
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

func (mq *mqPlugin) hideSecrets(values url.Values) url.Values {
	params := url.Values{}
	for key, array := range values {
		for _, value := range array {
			if mq.isSecretParameter(key) {
				params.Add(key, "xxxxx")
			} else {
				params.Add(key, value)
			}
		}
	}
	return params
}

// extractParameters parses the URL and the form parameters and replaces the secrets
// with the string xxxxx. The parameters containing secrets are defined in mq.Hide_secrets.
// Returns the Request URI path and the (adjusted) parameters.
func (mq *mqPlugin) extractParameters(m *message, msg []byte) (path string, params string, err error) {
	var values url.Values

	u, err := url.Parse(string(m.requestURI))
	if err != nil {
		return
	}
	values = u.Query()
	path = u.Path

	paramsMap := mq.hideSecrets(values)

	if m.contentLength > 0 && bytes.Contains(m.contentType, []byte("urlencoded")) {

		values, err = url.ParseQuery(string(msg[m.bodyOffset:]))
		if err != nil {
			return
		}

		for key, value := range mq.hideSecrets(values) {
			paramsMap[key] = value
		}
	}

	params = paramsMap.Encode()
	if isDetailed {
		detailedf("Form parameters: %s", params)
	}
	return
}

func (mq *mqPlugin) isSecretParameter(key string) bool {
	for _, keyword := range mq.hideKeywords {
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
