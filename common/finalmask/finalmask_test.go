package finalmask

import (
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// writesConn keeps each write of the mask apart.
type writesConn struct {
	net.Conn
	access sync.Mutex
	writes [][]byte
}

func (c *writesConn) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *writesConn) Close() error { return nil }

func (c *writesConn) SetDeadline(time.Time) error      { return nil }
func (c *writesConn) SetWriteDeadline(time.Time) error { return nil }

func hello(size int) []byte {
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	payload[0] = 1 // ClientHello
	return append([]byte{22, 3, 1, byte(size >> 8), byte(size)}, payload...)
}

// records reads TLS records back: their payload joined and their sizes.
func records(t *testing.T, stream []byte) ([]byte, []int) {
	t.Helper()
	var payload []byte
	var sizes []int
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 5)
		require.Equal(t, []byte{22, 3, 1}, stream[:3])
		size := int(stream[3])<<8 | int(stream[4])
		require.GreaterOrEqual(t, len(stream), 5+size)
		payload = append(payload, stream[5:5+size]...)
		sizes = append(sizes, size)
		stream = stream[5+size:]
	}
	return payload, sizes
}

func masked(t *testing.T, content string) (*fragmentConn, *writesConn) {
	t.Helper()
	var options option.FinalMaskOptions
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	masks, err := New(&options)
	require.NoError(t, err)
	under := &writesConn{}
	conn := masks.Client(under).(*fragmentConn)
	return conn, under
}

func TestHelloInRecordsOneWrite(t *testing.T) {
	t.Parallel()
	for range 20 {
		conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"11-24","delay":0}]}`)
		message := hello(1521)
		n, err := conn.Write(message)
		require.NoError(t, err)
		require.Equal(t, len(message), n)
		require.Len(t, under.writes, 1, "a single delay of 0: one write")
		payload, sizes := records(t, under.writes[0])
		require.Equal(t, message[5:], payload)
		for _, size := range sizes[:len(sizes)-1] {
			require.True(t, size >= 11 && size <= 23, "a record of %d bytes", size)
		}
		require.True(t, sizes[len(sizes)-1] >= 1 && sizes[len(sizes)-1] <= 23)
		require.Greater(t, len(sizes), 1521/24)
	}
}

func TestHelloRecordsEachAWriteWithDelay(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"200","delay":"1-2"}]}`)
	message := hello(1000)
	_, err := conn.Write(message)
	require.NoError(t, err)
	require.Len(t, under.writes, 5)
	payload, sizes := records(t, bytes.Join(under.writes, nil))
	require.Equal(t, message[5:], payload)
	require.Equal(t, []int{200, 200, 200, 200, 200}, sizes)
}

func TestHelloLengthsAndMaxSplit(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","lengths":["1","5",{"from":100,"to":100}],"max_split":"4"}]}`)
	message := hello(600)
	_, err := conn.Write(message)
	require.NoError(t, err)
	payload, sizes := records(t, under.writes[0])
	require.Equal(t, message[5:], payload)
	require.Equal(t, []int{1, 5, 100, 494}, sizes, "the last of max_split pieces takes the rest")
}

func TestHelloOnlyTheFirstWrite(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"11-24"}]}`)
	plain := []byte("GET / HTTP/1.1\r\n\r\n")
	_, err := conn.Write(plain)
	require.NoError(t, err)
	require.True(t, conn.WriterReplaceable())
	message := hello(300)
	_, err = conn.Write(message)
	require.NoError(t, err)
	require.Equal(t, [][]byte{plain, message}, under.writes, "not a hello first: nothing is cut, and later writes are not looked at")
}

func TestHelloWithMoreAfterTheRecord(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"50"}]}`)
	message := hello(120)
	extra := []byte{23, 3, 3, 0, 1, 9}
	n, err := conn.Write(append(append([]byte(nil), message...), extra...))
	require.NoError(t, err)
	require.Equal(t, len(message)+len(extra), n)
	require.Len(t, under.writes, 2)
	payload, sizes := records(t, under.writes[0])
	require.Equal(t, message[5:], payload)
	require.Equal(t, []int{50, 50, 20}, sizes)
	require.Equal(t, extra, under.writes[1])
}

// Two masks go as Xray chains them, the last next to the socket (Xray-core
// transport/internet/finalmask/finalmask.go: NewFinalMask reverses the list). On the wire, with
// Xray 26.9.9 and 26.10.31 (podkop-exp lab/runs/2026-11-25-selcheck): [tlshello, 1-1] sends the
// hello in records, [1-1, tlshello] sends it as one record.
func TestMasksInXrayOrder(t *testing.T) {
	t.Parallel()
	const (
		hellos = `{"type":"fragment","packets":"tlshello","length":"11-24","delay":"0"}`
		pieces = `{"type":"fragment","packets":"1-1","length":"100-200","max_split":"2"}`
	)
	for range 20 {
		conn, under := masked(t, `{"tcp":[`+hellos+`,`+pieces+`]}`)
		message := hello(1521)
		n, err := conn.Write(message)
		require.NoError(t, err)
		require.Equal(t, len(message), n)
		require.Len(t, under.writes, 2, "the records in two TCP pieces")
		require.True(t, len(under.writes[0]) >= 100 && len(under.writes[0]) <= 199, "a first piece of %d bytes", len(under.writes[0]))
		payload, sizes := records(t, bytes.Join(under.writes, nil))
		require.Equal(t, message[5:], payload)
		require.Greater(t, len(sizes), 1521/24, "the hello in records of 11 to 23 bytes")

		conn, under = masked(t, `{"tcp":[`+pieces+`,`+hellos+`]}`)
		_, err = conn.Write(message)
		require.NoError(t, err)
		require.Len(t, under.writes, 2)
		require.Equal(t, message, bytes.Join(under.writes, nil), "the pieces are no whole record: the hello is not cut into records")
	}
}

func TestPacketsRange(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"2-3","length":"3"}]}`)
	for _, text := range []string{"first", "second", "third!", "fourth"} {
		_, err := conn.Write([]byte(text))
		require.NoError(t, err)
	}
	require.Equal(t, []string{"first", "sec", "ond", "thi", "rd!", "fourth"}, texts(under.writes))
	require.True(t, conn.WriterReplaceable())
}

func TestPacketsEvery(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","length":"4"}]}`)
	for _, text := range []string{"abcdefgh", "ijkl"} {
		_, err := conn.Write([]byte(text))
		require.NoError(t, err)
	}
	require.Equal(t, []string{"abcd", "efgh", "ijkl"}, texts(under.writes))
	require.False(t, conn.WriterReplaceable(), "every write is cut: the mask never steps aside")
}

func TestCloseEndsThePause(t *testing.T) {
	t.Parallel()
	conn, _ := masked(t, `{"tcp":[{"type":"fragment","packets":"1-1","length":"1","delay":"60000"}]}`)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("abc"))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("the pause did not end with the connection")
	}
}

func TestOptionErrors(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"another mask":        `{"tcp":[{"type":"header-custom"}]}`,
		"no length":           `{"tcp":[{"type":"fragment","packets":"tlshello"}]}`,
		"a last length of 0":  `{"tcp":[{"type":"fragment","lengths":["5","0-3"]}]}`,
		"packets from 0":      `{"tcp":[{"type":"fragment","packets":"0-2","length":"5"}]}`,
		"packets not a range": `{"tcp":[{"type":"fragment","packets":"hello","length":"5"}]}`,
	} {
		var options option.FinalMaskOptions
		err := json.Unmarshal([]byte(content), &options)
		if err == nil {
			_, err = New(&options)
		}
		require.Error(t, err, name)
	}
	masks, err := New(nil)
	require.NoError(t, err)
	require.Nil(t, masks)
}

func texts(writes [][]byte) []string {
	var result []string
	for _, write := range writes {
		result = append(result, string(write))
	}
	return result
}

func TestNotReplaceableBeforeTheFirstWrite(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"tcp":[{"type":"fragment","packets":"tlshello","length":"11-24"}]}`,
		`{"tcp":[{"type":"fragment","packets":"1-2","length":"3"}]}`,
		`{"tcp":[{"type":"fragment","length":"3"}]}`,
	} {
		conn, _ := masked(t, content)
		require.False(t, conn.WriterReplaceable(), "a copy loop must not reach the socket before the mask has cut: %s", content)
		require.True(t, conn.ReaderReplaceable())
	}
}

func TestHelloNotCut(t *testing.T) {
	t.Parallel()
	for name, first := range map[string][]byte{
		// a record of no byte, and a record after it: Xray would lose the header
		"an empty record": {22, 3, 1, 0, 0, 22, 3, 1, 0, 1, 1},
		// a handshake record that is not a ClientHello (type 2): not a client's first write
		"not a ClientHello": append([]byte{22, 3, 3, 0, 40, 2}, make([]byte, 39)...),
		// what only looks like a record: the salt of Shadowsocks starting with 0x16
		"not TLS": append([]byte{22, 9, 9, 0, 20, 1}, make([]byte, 30)...),
	} {
		conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"2"}]}`)
		n, err := conn.Write(first)
		require.NoError(t, err)
		require.Equal(t, len(first), n)
		require.Equal(t, [][]byte{first}, under.writes, name)
	}
}

func TestRangesAsXrayDrawsThem(t *testing.T) {
	t.Parallel()
	// crypto.RandBetween of Xray: "11-12" is always 11, "11-14" never 14
	for range 20 {
		conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"11-12","delay":0}]}`)
		_, err := conn.Write(hello(110))
		require.NoError(t, err)
		_, sizes := records(t, under.writes[0])
		require.Equal(t, []int{11, 11, 11, 11, 11, 11, 11, 11, 11, 11}, sizes)
	}
	seen := map[int]bool{}
	for range 50 {
		conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"tlshello","length":"11-14","delay":0}]}`)
		_, err := conn.Write(hello(600))
		require.NoError(t, err)
		_, sizes := records(t, under.writes[0])
		for _, size := range sizes[:len(sizes)-1] {
			seen[size] = true
		}
	}
	require.Equal(t, map[int]bool{11: true, 12: true, 13: true}, seen)
}

func TestHugeLength(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"1-1","lengths":["5","2147483647"]}]}`)
	_, err := conn.Write(bytes.Repeat([]byte{7}, 40))
	require.NoError(t, err)
	require.Equal(t, []int{5, 35}, sizesOf(under.writes))
}

func TestDeadlineEndsThePause(t *testing.T) {
	t.Parallel()
	conn, under := masked(t, `{"tcp":[{"type":"fragment","packets":"1-1","length":"1","delay":"60000"}]}`)
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))
	started := time.Now()
	n, err := conn.Write([]byte("abc"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Equal(t, 1, n, "the piece before the pause is written")
	require.Less(t, time.Since(started), 5*time.Second)
	require.Equal(t, []string{"a"}, texts(under.writes))
	require.NoError(t, conn.SetWriteDeadline(time.Time{}))
}

func sizesOf(writes [][]byte) []int {
	var sizes []int
	for _, write := range writes {
		sizes = append(sizes, len(write))
	}
	return sizes
}
