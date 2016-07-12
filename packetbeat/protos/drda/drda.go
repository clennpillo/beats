package drda

import (
	"time"
	"fmt"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

    "github.com/elastic/beats/packetbeat/config"
	_ "github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
)

var debugf = logp.MakeDebug("drda")
var detailedf = logp.MakeDebug("drdadetailed")

type parseState int

const (
	drdaStateStart parseState = iota
	drdaStateContent
)

type drdaConnectionData struct {
	Streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

type Ddm struct {
    Length   uint16
    Cor            uint16
    Format         uint8
    Length2        uint16
    Codepoint      uint16
}

type Parameter struct {
    Length        uint16
    Codepoint      uint16
    ASCIIData      string
    EBCDICData     string
}

type stream struct {
    tcptuple *common.TcpTuple
    data []byte
    parseOffset int
    parseState  parseState
    message *message
}

var stateStrings []string = []string{
	"Start",
	"Content",
}

type Drda struct {
    // config
    Ports         []int
    maxStoreRows  int
    maxRowLength  int
    Send_request  bool
    Send_response bool

	parserConfig parserConfig

    transactions       *common.Cache
    transactionTimeout time.Duration

    results publish.Transactions

    // function pointer for mocking
    //handleDrda func(drda *Drda, m *DrdaMessage, tcp *common.TcpTuple,
    //    dir uint8, raw_msg []byte)
}

var (
	isDebug    = false
	isDetailed = false
)

func drdaAbbrev(codepoint uint16) string{
	abbrev := drda_abbrev[codepoint]

	if abbrev == "" {
		return fmt.Sprint("unknown_",codepoint)
	}

	return abbrev
}

func (state parseState) String() string {
	return stateStrings[state]
}

func (drda *Drda) initDefaults() {
	drda.maxRowLength = 1024
	drda.maxStoreRows = 10
	drda.transactionTimeout = protos.DefaultTransactionExpiration
}

func (drda *Drda) setFromConfig(config config.Drda) error {

	drda.Ports = config.Ports
	
	if config.Max_row_length != 0 {
		drda.maxRowLength = config.Max_row_length
	}
	if config.Max_rows != 0 {
		drda.maxStoreRows = config.Max_rows
	}

	return nil
}

func (drda *Drda) GetPorts() []int {
	return drda.Ports
}

// Init initializes the Drda protocol analyser.
func (drda *Drda) Init(testMode bool, results publish.Transactions) error {
	drda.initDefaults()

	if !testMode {
		err := drda.setFromConfig(config.ConfigSingleton.Protocols.Drda)
		if err != nil {
			return err
		}
	}

	isDebug = logp.IsDebug("drda")
	isDetailed = logp.IsDebug("drdadetailed")

	drda.results = results

	return nil
}

func (stream *stream) PrepareForNewMessage() {
	stream.data = stream.data[stream.parseOffset:]
	stream.parseState = drdaStateStart
	stream.parseOffset = 0
	stream.message = nil
}

func (drda *Drda) ConnectionTimeout() time.Duration {
	return drda.transactionTimeout
}

//entry point
func (drda *Drda) Parse(pkt *protos.Packet, tcptuple *common.TcpTuple,
	dir uint8, private protos.ProtocolData) protos.ProtocolData {
	
	conn := ensureDrdaConnection(private)
	conn = drda.doParse(conn, pkt, tcptuple, dir)
	
	if conn == nil {
		return nil
	}
	return conn
}

func ensureDrdaConnection(private protos.ProtocolData) *drdaConnectionData {
	conn := getDrdaConnection(private)
	if conn == nil {
		conn = &drdaConnectionData{}
	}
	return conn
}

func getDrdaConnection(private protos.ProtocolData) *drdaConnectionData {
	if private == nil {
		return nil
	}

	priv, ok := private.(*drdaConnectionData)
	if !ok {
		logp.Warn("http connection data type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: http connection data not set")
		return nil
	}

	return priv
}

// Parse function is used to process TCP payloads.
func (drda *Drda) doParse(
	conn *drdaConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
) *drdaConnectionData {

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

		parser := newParser(&drda.parserConfig)
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
		drda.messageComplete(conn, tcptuple, dir, st)

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

// Called when the parser has identified the boundary
// of a message.
func (drda *Drda) messageComplete(
	conn *drdaConnectionData,
	tcptuple *common.TcpTuple,
	dir uint8,
	st *stream,
) {
	st.message.Raw = st.data[st.message.start:st.message.end]

	drda.handleDrda(conn, st.message, tcptuple, dir)
}


func (drda *Drda) handleDrda(
	conn *drdaConnectionData,
	m *message,
	tcptuple *common.TcpTuple,
	dir uint8,
) {

	m.TCPTuple = *tcptuple
	m.Direction = dir
//	m.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())
//	drda.hideHeaders(m)

	if m.IsRequest {
		if isDebug {
//			debugf("Received request with tuple: %s", m.TCPTuple)
		}
		conn.requests.append(m)
	} else {
		if isDebug {
//			debugf("Received response with tuple: %s", m.TCPTuple)
		}
		conn.responses.append(m)
		drda.correlate(conn)
	}
}

func (drda *Drda) correlate(conn *drdaConnectionData) {
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
		trans := drda.newTransaction(requ, resp)

		if isDebug {
			debugf("HTTP transaction completed")
		}
		drda.publishTransaction(trans)
	}
}


func (drda *Drda) newTransaction(requ, resp *message) common.MapStr {
	status := common.OK_STATUS
//	if resp.StatusCode >= 400 {
//		status = common.ERROR_STATUS
//	}

	// resp_time in milliseconds
	responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

//	path, params, err := drda.extractParameters(requ, requ.Raw)
//	if err != nil {
//		logp.Warn("http", "Fail to parse HTTP parameters: %v", err)
//	}

	src := common.Endpoint{
		Ip:   requ.TCPTuple.Src_ip.String(),
		Port: requ.TCPTuple.Src_port,
//		Proc: string(requ.CmdlineTuple.Src),
	}
	dst := common.Endpoint{
		Ip:   requ.TCPTuple.Dst_ip.String(),
		Port: requ.TCPTuple.Dst_port,
//		Proc: string(requ.CmdlineTuple.Dst),
	}
	if requ.Direction == tcp.TcpDirectionReverse {
		src, dst = dst, src
	}

    var sqlStr string

	// only one parameter SQLSTT in this map
	for _, value := range requ.parameters {
		sqlStr = value.ASCIIData
	}

	kpi := common.MapStr{}
	kpi["sql"] = sqlStr

//	requNotes := requ.Notes
	requBytesIn := uint64(requ.ddm.Length)
	
	event := common.MapStr{
		"@timestamp":   common.Time(requ.Ts),
		"type":         "drda",
		"status":       status,
		"responsetime": responseTime,
		"bytes_out":    requBytesIn,
		"bytes_in":     requBytesIn,
		"src":          &src,
		"dst":          &dst,
		"kpi": 		    kpi,
	}

	return event
}

func (drda *Drda) publishTransaction(event common.MapStr) {
	if drda.results == nil {
		return
	}
	drda.results.PublishTransaction(event)
}

func (drda *Drda) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	/*defer logp.Recover("GapInStream(drda) exception")
	if private == nil {
		return private, false
	}
	drdaData, ok := private.(drdaPrivateData)
	if !ok {
		return private, false
	}
	stream := drdaData.Data[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}
	if drda.messageGap(stream, nbytes) {
		// we need to publish from here
		drda.messageComplete(tcptuple, dir, stream)
	}
	// we always drop the TCP stream. Because it's binary and len based,
	// there are too few cases in which we could recover the stream (maybe
	// for very large blobs, leaving that as TODO)
	*/

	//TODO: handle GapInStream()

	logp.Err("Unhandled gap of %d bytes in TCP stream",nbytes)

	return private, true
}

func (drda *Drda) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	// TODO: check if we have data pending and either drop it to free
	// memory or send it up the stack.
	return private
}

func (drda *Drda) RemovalListener(data protos.ProtocolData){

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