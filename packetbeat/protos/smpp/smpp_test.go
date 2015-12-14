package smpp

import (
	"fmt"
	"encoding/hex"
	"testing"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/publisher"
	"github.com/stretchr/testify/assert"
)

type testParser struct {
	payloads []string
	smpp     *SMPP
	stream   *stream
}

var testParserConfig = parserConfig{}

func newTestParser(smpp *SMPP, payloads ...string) *testParser {
	if smpp == nil {
		smpp = smppModForTests()
	}
	tp := &testParser{
		smpp:     smpp,
		payloads: payloads,
		stream:   &stream{data: []byte{}, message: new(message)},
	}
	return tp
}

func (tp *testParser) parse() (*message, bool, bool) {
	st := tp.stream
	if len(tp.payloads) > 0 {
		st.data = append(st.data, tp.payloads[0]...)
		tp.payloads = tp.payloads[1:]
	}

	parser := newParser(&tp.smpp.parserConfig)
	ok, complete := parser.parse(st)
	return st.message, ok, complete
}

func smppModForTests() *SMPP {
	var smpp SMPP
	results := publisher.ChanClient{Channel: make(chan common.MapStr, 10)}
	smpp.Init(true, results)
	return &smpp
}

func testParse(smpp *SMPP, data string) (*message, bool, bool) {
	tp := newTestParser(smpp, data)
	return tp.parse()
}

func testParseStream(smpp *SMPP, st *stream) (bool, bool) {
	parser := newParser(&smpp.parserConfig)
	return parser.parse(st)
}

func TestHttpParser_simpleResponse(t *testing.T) {
	data := "SMPP/1.1 200 OK\r\n" +
		"Date: Tue, 14 Aug 2012 22:31:45 GMT\r\n" +
		"Expires: -1\r\n" +
		"Cache-Control: private, max-age=0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Server: gws\r\n" +
		"Content-Length: 0\r\n" +
		"X-XSS-Protection: 1; mode=block\r\n" +
		"X-Frame-Options: SAMEORIGIN\r\n" +
		"\r\n"
	message, ok, complete := testParse(nil, data)

	assert.True(t, ok)
	assert.True(t, complete)
	assert.False(t, message.IsRequest)
}

func TestSmppParser_simpleRequest(t *testing.T){
	hexData := "000000b600000005000000000001a83400050063617232676" +
	           	"f000101343931353137333034313738370004000000000000" +
				"00008269643a6263643438356432646666393437626661643" +
	            "834323031376138366463613634207375623a30303120646c" +
				"7672643a303031207375626d697420646174653a313531323" +
				"1303135313520646f6e6520646174653a3135313231303136" +
	            "313520737461743a44454c49565244206572723a303030207" +
				"46578743a5669656c656e"

	data, err := hex.DecodeString(hexData)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0xb6, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xa8, 0x34, 0x0, 0x5, 0x0, 0x63, 0x61, 0x72, 0x32, 0x67, 0x6f, 0x0, 0x1, 0x1, 0x34, 0x39, 0x31, 0x35, 0x31, 0x37, 0x33, 0x30, 0x34, 0x31, 0x37, 0x38, 0x37, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x82, 0x69, 0x64, 0x3a, 0x62, 0x63, 0x64, 0x34, 0x38, 0x35, 0x64, 0x32, 0x64, 0x66, 0x66, 0x39, 0x34, 0x37, 0x62, 0x66, 0x61, 0x64, 0x38, 0x34, 0x32, 0x30, 0x31, 0x37, 0x61, 0x38, 0x36, 0x64, 0x63, 0x61, 0x36, 0x34, 0x20, 0x73, 0x75, 0x62, 0x3a, 0x30, 0x30, 0x31, 0x20, 0x64, 0x6c, 0x76, 0x72, 0x64, 0x3a, 0x30, 0x30, 0x31, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x20, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x31, 0x35, 0x31, 0x32, 0x31, 0x30, 0x31, 0x35, 0x31, 0x35, 0x20, 0x64, 0x6f, 0x6e, 0x65, 0x20, 0x64, 0x61, 0x74, 0x65, 0x3a, 0x31, 0x35, 0x31, 0x32, 0x31, 0x30, 0x31, 0x36, 0x31, 0x35, 0x20, 0x73, 0x74, 0x61, 0x74, 0x3a, 0x44, 0x45, 0x4c, 0x49, 0x56, 0x52, 0x44, 0x20, 0x65, 0x72, 0x72, 0x3a, 0x30, 0x30, 0x30, 0x20, 0x74, 0x65, 0x78, 0x74, 0x3a, 0x56, 0x69, 0x65, 0x6c, 0x65, 0x6e}, data)
}

func TestHttpParser_censorPasswordGET(t *testing.T) {
	if testing.Verbose() {
		logp.LogInit(logp.LOG_DEBUG, "", false, true, []string{"smpp", "smppdetailed"})
	}

	smpp := smppModForTests()
	smpp.HideKeywords = []string{"password"}
	smpp.parserConfig.SendHeaders = true
	smpp.parserConfig.SendAllHeaders = true
	smpp.SendRequest = false
	smpp.SendResponse = false

	hexData := "000000b600000005000000000001a83400050063617232676" +
	"f000101343931353137333034313738370004000000000000" +
	"00008269643a6263643438356432646666393437626661643" +
	"834323031376138366463613634207375623a30303120646c" +
	"7672643a303031207375626d697420646174653a313531323" +
	"1303135313520646f6e6520646174653a3135313231303136" +
	"313520737461743a44454c49565244206572723a303030207" +
	"46578743a5669656c656e"

	data, err := hex.DecodeString(hexData)
	assert.Nil(t, err, "Faile to parse hexData")

	st := &stream{data: data, message: new(message)}

	ok, complete := testParseStream(smpp, st)
	fmt.Printf("%+v\n", st.message.Message);
	assert.True(t, ok, "Parsing returned error")
	assert.True(t, complete, "Expecting a complete message")
	assert.Equal(t, common.NetString(data), st.message.Message)
	assert.Equal(t, hexData, st.message.HexMessage)
}
