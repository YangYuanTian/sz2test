package gtpserver

import "context"

type GtpServer struct {
}

func (g *GtpServer) MsgHandle(ctx context.Context, msg []byte) error {
	return nil
}
