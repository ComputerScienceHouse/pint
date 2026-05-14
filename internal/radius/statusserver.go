// internal/radius/statusserver.go
package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// FreeRADIUS RADIUS protocol constants.
const (
	radCodeStatusServer  = 12
	radCodeAccessAccept  = 2
	radAttrVendorSpecific = 26
	radAttrMessageAuth   = 80
	frVendorID           = uint32(11344)
)

// FreeRADIUS vendor attribute types (dictionary.freeradius, vendor 11344).
const (
	frAttrStatisticsType        = byte(127) // FreeRADIUS-Statistics-Type
	frAttrTotalAccessRequests   = byte(128) // FreeRADIUS-Total-Access-Requests
	frAttrTotalAccessAccepts    = byte(129) // FreeRADIUS-Total-Access-Accepts
	frAttrTotalAccessRejects    = byte(130) // FreeRADIUS-Total-Access-Rejects
	frAttrTotalAccessChallenges = byte(131) // FreeRADIUS-Total-Access-Challenges
	frAttrAuthMalformed         = byte(134) // FreeRADIUS-Total-Auth-Malformed-Requests
	frAttrAuthInvalid           = byte(135) // FreeRADIUS-Total-Auth-Invalid-Requests
	frAttrAuthDropped           = byte(136) // FreeRADIUS-Total-Auth-Dropped-Requests
	frAttrQueueLenAuth   = byte(164) // FreeRADIUS-Queue-Len-Auth
	frAttrStatsStartTime        = byte(176) // FreeRADIUS-Stats-Start-Time
	frAttrQueuePPSIn            = byte(181) // FreeRADIUS-Queue-PPS-In
	frAttrQueuePPSOut           = byte(182) // FreeRADIUS-Queue-PPS-Out
	frAttrThreadsActive         = byte(193) // FreeRADIUS-Stats-Threads-Active
	frAttrThreadsTotal          = byte(194) // FreeRADIUS-Stats-Threads-Total
	frAttrThreadsMax            = byte(195) // FreeRADIUS-Stats-Threads-Max
)

// RADIUSStats holds global authentication and internal statistics from a single FreeRADIUS process.
type RADIUSStats struct {
	AccessRequests   uint32
	AccessAccepts    uint32
	AccessRejects    uint32
	AccessChallenges uint32

	AuthMalformed uint32
	AuthDropped   uint32
	AuthInvalid   uint32

	ThreadsActive uint32
	ThreadsTotal  uint32
	ThreadsMax    uint32
	QueueLenAuth  uint32
	QueuePPSIn    uint32
	QueuePPSOut   uint32

	StartTime string // formatted UTC string, empty if unavailable
}

// HasOutcomes returns true when at least one auth has reached a final outcome (accept or reject).
// EAP challenges are excluded — they are not authentication outcomes.
func (s *RADIUSStats) HasOutcomes() bool {
	return s.AccessAccepts+s.AccessRejects > 0
}

// SuccessRate returns Accepts/(Accepts+Rejects) as a percentage (0–100).
// Uses final outcomes only; challenges are excluded to avoid inflated denominators with EAP-TLS.
func (s *RADIUSStats) SuccessRate() int {
	denom := s.AccessAccepts + s.AccessRejects
	if denom == 0 {
		return 0
	}
	return int(s.AccessAccepts * 100 / denom)
}

// QueryRADIUSStats sends a Status-Server packet (type 0x11 = auth + internal) to addr
// and returns the parsed statistics. addr is "host:port". Returns nil on any error
// so callers can treat it as best-effort.
func QueryRADIUSStats(ctx context.Context, addr, secret string) *RADIUSStats {
	deadline := time.Now().Add(1 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn, err := net.DialTimeout("udp", addr, 1*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	// Query auth (0x01) + internal (0x10) = 0x11.
	pkt, err := buildStatusServerPacket([]byte(secret), 0x11)
	if err != nil {
		return nil
	}
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	stats, err := parseStatsResponse(buf[:n])
	if err != nil {
		return nil
	}
	return stats
}

// buildStatusServerPacket constructs a Status-Server packet per RFC 5997.
// Request Authenticator = random 16 bytes; Message-Authenticator = HMAC-MD5.
func buildStatusServerPacket(secret []byte, statsType uint32) ([]byte, error) {
	vsaAttr := makeVSA(frVendorID, frAttrStatisticsType, statsType)

	// Message-Authenticator placeholder (16 zero bytes).
	maAttr := makeAttr(radAttrMessageAuth, make([]byte, 16))

	attrs := append(vsaAttr, maAttr...)
	pkt := make([]byte, 20+len(attrs))
	pkt[0] = radCodeStatusServer
	if _, err := rand.Read(pkt[1:2]); err != nil { // random identifier
		return nil, err
	}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	if _, err := rand.Read(pkt[4:20]); err != nil { // random Request Authenticator (RFC 5997 §2.2)
		return nil, err
	}
	copy(pkt[20:], attrs)

	// Message-Authenticator starts at byte 20 + len(vsaAttr) + 2 (skip type+len of MA attr).
	maValueOffset := 20 + len(vsaAttr) + 2

	// HMAC-MD5(key=secret, msg=packet with MA value field zeroed).
	mac := hmac.New(md5.New, secret)
	mac.Write(pkt[:maValueOffset])
	mac.Write(make([]byte, 16))
	mac.Write(pkt[maValueOffset+16:])
	copy(pkt[maValueOffset:maValueOffset+16], mac.Sum(nil))

	return pkt, nil
}

func makeAttr(t byte, v []byte) []byte {
	a := make([]byte, 2+len(v))
	a[0] = t
	a[1] = byte(len(a))
	copy(a[2:], v)
	return a
}

// makeVSA builds a Vendor-Specific Attribute (type 26) with a uint32 value.
func makeVSA(vendorID uint32, vendorType byte, value uint32) []byte {
	// VSA body: vendor-id(4) + vendor-type(1) + vendor-length(1) + value(4)
	body := make([]byte, 10)
	binary.BigEndian.PutUint32(body[0:4], vendorID)
	body[4] = vendorType
	body[5] = 6 // vendor-type(1) + vendor-length(1) + value(4)
	binary.BigEndian.PutUint32(body[6:10], value)
	return makeAttr(radAttrVendorSpecific, body)
}

func parseStatsResponse(data []byte) (*RADIUSStats, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("response too short")
	}
	if data[0] != radCodeAccessAccept {
		return nil, fmt.Errorf("unexpected response code %d", data[0])
	}
	pktLen := int(binary.BigEndian.Uint16(data[2:4]))
	if pktLen > len(data) {
		pktLen = len(data)
	}

	stats := &RADIUSStats{}
	attrs := data[20:pktLen]

	for len(attrs) >= 2 {
		t := attrs[0]
		l := int(attrs[1])
		if l < 2 || l > len(attrs) {
			break
		}
		v := attrs[2:l]
		attrs = attrs[l:]

		if t != radAttrVendorSpecific || len(v) < 10 {
			continue
		}
		if binary.BigEndian.Uint32(v[0:4]) != frVendorID {
			continue
		}
		vType := v[4]
		vLen := int(v[5]) // length of vendor-type(1) + vendor-length(1) + value
		if vLen < 6 || 4+vLen > len(v) {
			continue // expect exactly a uint32 value (vLen = 6)
		}
		val := binary.BigEndian.Uint32(v[6:10])

		switch vType {
		case frAttrTotalAccessRequests:
			stats.AccessRequests = val
		case frAttrTotalAccessAccepts:
			stats.AccessAccepts = val
		case frAttrTotalAccessRejects:
			stats.AccessRejects = val
		case frAttrTotalAccessChallenges:
			stats.AccessChallenges = val
		case frAttrAuthMalformed:
			stats.AuthMalformed = val
		case frAttrAuthInvalid:
			stats.AuthInvalid = val
		case frAttrAuthDropped:
			stats.AuthDropped = val
		case frAttrQueueLenAuth:
			stats.QueueLenAuth = val
		case frAttrQueuePPSIn:
			stats.QueuePPSIn = val
		case frAttrQueuePPSOut:
			stats.QueuePPSOut = val
		case frAttrThreadsActive:
			stats.ThreadsActive = val
		case frAttrThreadsTotal:
			stats.ThreadsTotal = val
		case frAttrThreadsMax:
			stats.ThreadsMax = val
		case frAttrStatsStartTime:
			stats.StartTime = time.Unix(int64(val), 0).UTC().Format("Jan 2 2006 15:04:05 UTC")
		}
	}

	return stats, nil
}
