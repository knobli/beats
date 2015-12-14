package smpp

import (
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
)

var debugf = logp.MakeDebug("smpp")
var detailedf = logp.MakeDebug("smppdetailed")

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

type smppConnectionData struct {
	Streams   [2]*stream
	requests  messageList
	responses messageList
}

type messageList struct {
	head, tail *message
}

// SMPP application level protocol analyser plugin.
type SMPP struct {
	// config
	Ports               []int
	SendRequest         bool
	SendResponse        bool
	SplitCookie         bool
	HideKeywords        []string
	RedactAuthorization bool

	parserConfig parserConfig

	transactionTimeout time.Duration

	results publisher.Client
}

var (
	isDebug    = false
	isDetailed = false
)

func (smpp *SMPP) initDefaults() {
	smpp.SendRequest = false
	smpp.SendResponse = false
	smpp.RedactAuthorization = false
	smpp.transactionTimeout = protos.DefaultTransactionExpiration
}

func (smpp *SMPP) setFromConfig(config config.Http) (err error) {

	smpp.Ports = config.Ports

	if config.SendRequest != nil {
		smpp.SendRequest = *config.SendRequest
	}
	if config.SendResponse != nil {
		smpp.SendResponse = *config.SendResponse
	}
	smpp.HideKeywords = config.Hide_keywords
	if config.Redact_authorization != nil {
		smpp.RedactAuthorization = *config.Redact_authorization
	}

	if config.Send_all_headers != nil {
		smpp.parserConfig.SendHeaders = true
		smpp.parserConfig.SendAllHeaders = true
	} else {
		if len(config.Send_headers) > 0 {
			smpp.parserConfig.SendHeaders = true

			smpp.parserConfig.HeadersWhitelist = map[string]bool{}
			for _, hdr := range config.Send_headers {
				smpp.parserConfig.HeadersWhitelist[strings.ToLower(hdr)] = true
			}
		}
	}

	if config.Split_cookie != nil {
		smpp.SplitCookie = *config.Split_cookie
	}

	if config.Real_ip_header != nil {
		smpp.parserConfig.RealIPHeader = strings.ToLower(*config.Real_ip_header)
	}

	if config.TransactionTimeout != nil && *config.TransactionTimeout > 0 {
		smpp.transactionTimeout = time.Duration(*config.TransactionTimeout) * time.Second
	}

	return nil
}

// GetPorts lists the port numbers the SMPP protocol analyser will handle.
func (smpp *SMPP) GetPorts() []int {
	return smpp.Ports
}

// Init initializes the SMPP protocol analyser.
func (smpp *SMPP) Init(testMode bool, results publisher.Client) error {
	smpp.initDefaults()

	if !testMode {
		err := smpp.setFromConfig(config.ConfigSingleton.Protocols.Http)
		if err != nil {
			return err
		}
	}

	isDebug = logp.IsDebug("smpp")
	isDetailed = logp.IsDebug("smppdetailed")

	smpp.results = results

	return nil
}

// messageGap is called when a gap of size `nbytes` is found in the
// tcp stream. Decides if we can ignore the gap or it's a parser error
// and we need to drop the stream.
func (smpp *SMPP) messageGap(s *stream, nbytes int) (ok bool, complete bool) {
	return false, false
}

func (st *stream) PrepareForNewMessage() {
	st.data = st.data[:]
	st.parseState = stateStart
	st.parseOffset = 0
	st.bodyReceived = 0
	st.message = nil
}

// Called when the parser has identified the boundary
// of a message.
func (smpp *SMPP) messageComplete(
	tcptuple *common.TcpTuple,
	dir uint8,
	st *stream,
) {
	smpp.handleSMPP(st.message, tcptuple, dir)
}

// ConnectionTimeout returns the configured SMPP transaction timeout.
func (smpp *SMPP) ConnectionTimeout() time.Duration {
	return smpp.transactionTimeout
}

// Parse function is used to process TCP payloads.
func (smpp *SMPP) Parse(
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseHttp exception")

	smpp.doParse(pkt, tcptuple, dir)
	return nil
}


// Parse function is used to process TCP payloads.
func (smpp *SMPP) doParse(
	pkt *protos.Packet,
	tcptuple *common.TcpTuple,
	dir uint8,
) {

	if isDetailed {
		detailedf("Payload received: [%s]", pkt.Payload)
	}

	st := newStream(pkt, tcptuple)

	for len(st.data) > 0 {
		if st.message == nil {
			st.message = &message{Ts: pkt.Ts}
		}

		parser := newParser(&smpp.parserConfig)
		ok, complete := parser.parse(st)
		if !ok {
			return
		}

		if !complete {
			break
		}

		// all ok, ship it
		smpp.messageComplete(tcptuple, dir, st)

		// and reset stream for next message
		st.PrepareForNewMessage()
	}
}

func newStream(pkt *protos.Packet, tcptuple *common.TcpTuple) *stream {
	return &stream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &message{Ts: pkt.Ts},
	}
}

// ReceivedFin will be called when TCP transaction is terminating.
func (smpp *SMPP) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	return nil
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due
// to packet loss).
func (smpp *SMPP) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInStream(smpp) exception")
	// don't drop the stream, we can ignore the gap
	return private, false
}

func (smpp *SMPP) handleSMPP(
	m *message,
	tcptuple *common.TcpTuple,
	dir uint8,
) {

	m.TCPTuple = *tcptuple
	m.Direction = dir
	m.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())

	trans := smpp.newTransaction(m)
	smpp.publishTransaction(trans)
}

func (smpp *SMPP) newTransaction(requ *message) common.MapStr {
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

	event := common.MapStr{
		"@timestamp":   common.Time(requ.Ts),
		"type":         "smpp",
		"messageTest":	requ.Message,
		"payload":		requ.HexMessage,
		"src":          &src,
		"dst":          &dst,
	}

	if len(requ.RealIP) > 0 {
		event["real_ip"] = requ.RealIP
	}

	return event
}

func (smpp *SMPP) publishTransaction(event common.MapStr) {
	if smpp.results == nil {
		return
	}
	smpp.results.PublishEvent(event)
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
