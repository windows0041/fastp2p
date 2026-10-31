package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
)

type natHandler struct {
}

func (h *natHandler) handleMessage(ctx *msgContext) error {
	head := openP2PHeader{}
	err := binary.Read(bytes.NewReader(ctx.msg[:openP2PHeaderSize]), binary.LittleEndian, &head)
	if err != nil {
		gLog.Println(LvERROR, "handle message process header error:", err)
		return err
	}
	sess, ok := ctx.sess.(*UDPSession)
	if !ok {
		gLog.Println(LvERROR, "interface conversion error")
		return errors.New("interface conversion error")
	}
	switch head.MainType {
	case MsgNATDetect:
		// gLogger.Println(LvINFO, string(msg))
		isPublicIP := 0
		req := NatDetectReq{}
		err = json.Unmarshal(ctx.msg[openP2PHeaderSize:], &req)
		if err != nil {
			gLog.Println(LvERROR, "wrong NatDetectReq:", err)
			return err
		}
		natRsp := NatDetectRsp{
			IP:         sess.ra.IP.String(),
			Port:       sess.ra.Port,
			IsPublicIP: isPublicIP}
		if head.SubType == 1 {
			if req.EchoPort < 1 || req.EchoPort > 65535 {
				return errors.New("invalid echo port")
			}
			natRsp.Port = req.EchoPort
			echo := *sess
			echo.ra = &net.UDPAddr{IP: sess.ra.IP, Port: req.EchoPort}
			return echo.write(MsgNATDetect, head.SubType, natRsp)
		}
		sess.write(MsgNATDetect, 0, natRsp)
		// gLog.Printf(LvINFO, "%s nat detect ok", sess.ra.IP.String())
	default:
		return nil
	}
	return nil
}
