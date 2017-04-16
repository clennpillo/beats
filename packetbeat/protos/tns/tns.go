package tns

import (
	"bytes"
	"net/url"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
)

var debugf = logp.MakeDebug("tns")
var detailedf = logp.MakeDebug("tnsdetailed")

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

type stream struct {
	tcptuple *common.TcpTuple

	data []byte

	parseOffset  int
	parseState   parserState
	bodyReceived int

	message *message
}

type tnsConnectionData struct {
	Streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// Tns application level protocol analyser plugin.
type Tns struct {
	// config
	Ports               []int
	SendRequest         bool
	SendResponse        bool
	SplitCookie         bool
	HideKeywords        []string
	RedactAuthorization bool
	IncludeBodyFor      []string

	parserConfig parserConfig

	transactionTimeout time.Duration

	results publish.Transactions
}

var (
	isDebug    = false
	isDetailed = false
)

func (tns *Tns) initDefaults() {
	tns.transactionTimeout = protos.DefaultTransactionExpiration
}

func (tns *Tns) setFromConfig(config config.Tns) error {
	tns.Ports = config.Ports
	
	return nil
}

// GetPorts lists the port numbers the Tns protocol analyser will handle.
func (tns *Tns) GetPorts() []int {
	return tns.Ports
}

// Init initializes the Tns protocol analyser.
func (tns *Tns) Init(testMode bool, results publish.Transactions) error {
	tns.initDefaults()

	if !testMode {
		err := tns.setFromConfig(config.ConfigSingleton.Protocols.Tns)
		if err != nil {
			return err
		}
	}

	isDebug = logp.IsDebug("tns")
	isDetailed = logp.IsDebug("tnsdetailed")

	tns.results = results

	return nil
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (tns *Tns) messageGap(s *stream, nbytes int) (ok bool, complete bool) {

//	m := s.message
//	switch s.parseState {
//	case stateStart, stateHeaders:
//		// we know we cannot recover from these
//		return false, false
//	case stateBody:
//		if isDebug {
//			debugf("gap in body: %d", nbytes)
//		}
//
//		if m.IsRequest {
//			m.Notes = append(m.Notes, "Packet loss while capturing the request")
//		} else {
//			m.Notes = append(m.Notes, "Packet loss while capturing the response")
//		}
//		if !m.hasContentLength && (bytes.Equal(m.connection, constClose) ||
//			(isVersion(m.version, 1, 0) && !bytes.Equal(m.connection, constKeepAlive))) {
//
//			s.bodyReceived += nbytes
//			m.ContentLength += nbytes
//			return true, false
//		} else if len(s.data[s.parseOffset:])+nbytes >= m.ContentLength-s.bodyReceived {
//			// we're done, but the last portion of the data is gone
//			m.end = s.parseOffset
//			return true, true
//		} else {
//			s.bodyReceived += nbytes
//			return true, false
//		}
//	}
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
func (tns *Tns) messageComplete(
	conn *tnsConnectionData,
	tcptuple *common.TcpTuple,
	dir uint8,
	st *stream,
) {
	st.message.Raw = st.data[st.message.start:st.message.end]

	tns.handleTns(conn, st.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured Tns transaction timeout.
func (tns *Tns) ConnectionTimeout() time.Duration {
	return tns.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (tns *Tns) Parse(
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseHttp exception")

	conn := ensureTnsConnection(private)
	conn = tns.doParse(conn, pkt, tcptuple, dir)
	if conn == nil {
		return nil
	}
	return conn
}

func ensureTnsConnection(private protos.ProtocolData) *tnsConnectionData {
	conn := getTnsConnection(private)
	if conn == nil {
		conn = &tnsConnectionData{}
	}
	return conn
}

func getTnsConnection(private protos.ProtocolData) *tnsConnectionData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*tnsConnectionData)
	if !ok {
		logp.Warn("tns connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: tns connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (tns *Tns) doParse(
	conn *tnsConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
) *tnsConnectionData {

	if isDetailed {
		detailedf("Payload received: [%s]", pkt.Payload)
	}

	st := conn.Streams[dir]
	if st == nil {
		st = newStream(pkt, tcptuple)
		conn.Streams[dir] = st
	} else {
		// concatenate bytes
		st.data = append(st.data, pkt.Payload...)
		if len(st.data) > tcp.TCP_MAX_DATA_IN_STREAM {
			if isDebug {
				debugf("Stream data too large, dropping TCP stream")
			}
			conn.Streams[dir] = nil
			return conn
		}
	}

	for len(st.data) > 0 {
		if st.message == nil {
			st.message = &message{Ts: pkt.Ts}
		}

		parser := newParser(&tns.parserConfig)
		ok, complete := parser.parse(st)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.Streams[dir] = nil
			return conn
		}

		if !complete {
			// wait for more data
			break
		}

		// all ok, ship it
		tns.messageComplete(conn, tcptuple, dir, st)

		// and reset stream for next message
		st.PrepareForNewMessage()
	}

	return conn
}

func newStream(pkt *protos.Packet, tcptuple *common.TcpTuple) *stream {
	return &stream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &message{Ts: pkt.Ts},
	}
}

// ReceivedFin will be called when TCP transaction is terminating.
func (tns *Tns) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	conn := getTnsConnection(private)
	if conn == nil {
		return private
	}

	stream := conn.Streams[dir]
	if stream == nil {
		return conn
	}

	// send whatever data we got so far as complete. This
	// is needed for the Tns/1.0 without Content-Length situation.
	if stream.message != nil && len(stream.data[stream.message.start:]) > 0 {
		stream.message.Raw = stream.data[stream.message.start:]
		tns.handleTns(conn, stream.message, tcptuple, dir)

		// and reset message. Probably not needed, just to be sure.
		stream.PrepareForNewMessage()
	}

	return conn
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
func (tns *Tns) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(tns) exception")

	conn := getTnsConnection(private)
	if conn == nil {
		return private, false
	}

	stream := conn.Streams[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	ok, complete := tns.messageGap(stream, nbytes)
	if isDetailed {
		detailedf("messageGap returned ok=%v complete=%v", ok, complete)
	}
	if !ok {
		// on errors, drop stream
		conn.Streams[dir] = nil
		return conn, true
	}

	if complete {
		// Current message is complete, we need to publish from here
		tns.messageComplete(conn, tcptuple, dir, stream)
	}

	// don't drop the stream, we can ignore the gap
	return private, false
}
	
func (tns *Tns) RemovalListener(data protos.ProtocolData) {
	
}		

func (tns *Tns) handleTns(
	conn *tnsConnectionData,
	m *message,
	tcptuple *common.TcpTuple,
	dir uint8,
) {

	m.TCPTuple = *tcptuple
	m.Direction = dir
	m.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())
	tns.hideHeaders(m)

	if m.IsRequest {
		if isDebug {
			debugf("Received request with tuple: %s", m.TCPTuple)
		}
		conn.requests.append(m)
	} else {
		if isDebug {
			debugf("Received response with tuple: %s", m.TCPTuple)
		}
		conn.responses.append(m)
		tns.correlate(conn)
	}
}

func (tns *Tns) correlate(conn *tnsConnectionData) {
	// drop responses with missing requests
	if conn.requests.empty() {
		for !conn.responses.empty() {
			logp.Warn("Response from unknown transaction. Ingoring.")
			conn.responses.pop()
		}
		return
	}

	// merge requests with responses into transactions
	for !conn.responses.empty() && !conn.requests.empty() {
		requ := conn.requests.pop()
		resp := conn.responses.pop()
		trans := tns.newTransaction(requ, resp)

		if isDebug {
			debugf("Tns transaction completed")
		}
		tns.publishTransaction(trans)
	}
}

func (tns *Tns) newTransaction(requ, resp *message) common.MapStr {
	status := common.OK_STATUS
	if resp.StatusCode >= 400 {
		status = common.ERROR_STATUS
	}

	// resp_time in milliseconds
	responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

	_, _, err := tns.extractParameters(requ, requ.Raw)
	if err != nil {
		logp.Warn("tns", "Fail to parse Tns parameters: %v", err)
	}

	src := common.Endpoint{
		Ip:   requ.TCPTuple.Src_ip.String(),
		Port: requ.TCPTuple.Src_port,
		Proc: string(requ.CmdlineTuple.Src),
	}
	dst := common.Endpoint{
		Ip:   requ.TCPTuple.Dst_ip.String(),
		Port: requ.TCPTuple.Dst_port,
		Proc: string(requ.CmdlineTuple.Dst),
	}
	if requ.Direction == tcp.TcpDirectionReverse {
		src, dst = dst, src
	}

	kpi := common.MapStr{
		"sql":            requ.sql,
	}
	
	event := common.MapStr{
		"@timestamp":   common.Time(requ.Ts),
		"type":         "tns",
		"status":       status,
		"responsetime": responseTime,
		"bytes_out":    resp.Size,
		"bytes_in":     requ.Size,
		"src":          &src,
		"dst":          &dst,
		"kpi":			kpi,
	}

	if tns.SendRequest {
		event["request"] = string(tns.cutMessageBody(requ))
	}
	if tns.SendResponse {
		event["response"] = string(tns.cutMessageBody(resp))
	}
	if len(requ.Notes)+len(resp.Notes) > 0 {
		event["notes"] = append(requ.Notes, resp.Notes...)
	}
	if len(requ.RealIP) > 0 {
		event["real_ip"] = requ.RealIP
	}

	return event
}

func (tns *Tns) publishTransaction(event common.MapStr) {
	if tns.results == nil {
		return
	}
	tns.results.PublishTransaction(event)
}

func (tns *Tns) collectHeaders(m *message) interface{} {
	if !tns.SplitCookie {
		return m.Headers
	}

	cookie := "cookie"
	if !m.IsRequest {
		cookie = "set-cookie"
	}

	hdrs := map[string]interface{}{}
	for name, value := range m.Headers {
		if name == cookie {
			hdrs[name] = splitCookiesHeader(string(value))
		} else {
			hdrs[name] = value
		}
	}
	return hdrs
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

func (tns *Tns) cutMessageBody(m *message) []byte {
	cutMsg := []byte{}

	// add headers always
	cutMsg = m.Raw[:m.bodyOffset]

	// add body
	if len(m.ContentType) == 0 || tns.shouldIncludeInBody(m.ContentType) {
		if len(m.chunkedBody) > 0 {
			cutMsg = append(cutMsg, m.chunkedBody...)
		} else {
			if isDebug {
				debugf("Body to include: [%s]", m.Raw[m.bodyOffset:])
			}
			cutMsg = append(cutMsg, m.Raw[m.bodyOffset:]...)
		}
	}

	return cutMsg
}

func (tns *Tns) shouldIncludeInBody(contenttype []byte) bool {
	includedBodies := tns.IncludeBodyFor
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

func (tns *Tns) hideHeaders(m *message) {
	if !m.IsRequest || !tns.RedactAuthorization {
		return
	}

	msg := m.Raw

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
		if len(m.Headers[header]) > 0 {
			m.Headers[header] = []byte("*")
		}
	}

	m.Raw = msg
}

func (tns *Tns) hideSecrets(values url.Values) url.Values {
	params := url.Values{}
	for key, array := range values {
		for _, value := range array {
			if tns.isSecretParameter(key) {
				params.Add(key, "xxxxx")
			} else {
				params.Add(key, value)
			}
		}
	}
	return params
}

// extractParameters parses the URL and the form parameters and replaces the secrets
// with the string xxxxx. The parameters containing secrets are defined in tns.Hide_secrets.
// Returns the Request URI path and the (ajdusted) parameters.
func (tns *Tns) extractParameters(m *message, msg []byte) (path string, params string, err error) {
	var values url.Values

	u, err := url.Parse(string(m.RequestURI))
	if err != nil {
		return
	}
	values = u.Query()
	path = u.Path

	paramsMap := tns.hideSecrets(values)

	if m.ContentLength > 0 && bytes.Contains(m.ContentType, []byte("urlencoded")) {
		values, err = url.ParseQuery(string(msg[m.bodyOffset:]))
		if err != nil {
			return
		}

		for key, value := range tns.hideSecrets(values) {
			paramsMap[key] = value
		}
	}
	params = paramsMap.Encode()

	if isDetailed {
		detailedf("Parameters: %s", params)
	}

	return
}

func (tns *Tns) isSecretParameter(key string) bool {
	for _, keyword := range tns.HideKeywords {
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