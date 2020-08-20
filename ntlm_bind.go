package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// NextMessageID get next msg id
func (l *Conn) NextMessageID() int64 {
	return l.nextMessageID()
}

// SendAndRecvPacket send/recv msg
func (l *Conn) SendAndRecvPacket(req *ber.Packet) (*ber.Packet, error) {

	msgCtx, err := l.sendMessage(req)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}

	var packet *ber.Packet
	packet, err = packetResponse.ReadPacket()
	if err != nil {
		return nil, err
	}

	return packet, nil
}
