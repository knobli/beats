package smpp

import (
	"time"
	"encoding/hex"

	"github.com/elastic/beats/libbeat/common"
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

	RealIP       common.NetString

	Message   common.NetString
	HexMessage   string


	next		*message
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

func newParser(config *parserConfig) *parser {
	return &parser{config: config}
}

func (parser *parser) parse(s *stream) (bool, bool) {
	m := s.message

	ok, complete := parser.parseSMPPLine(s, m)

	return ok, complete
}

func (*parser) parseSMPPLine(s *stream, m *message) (cont, ok bool) {
	m.HexMessage = hex.EncodeToString(s.data)
	m.Message = common.NetString(s.data)
	return true, true;
}
