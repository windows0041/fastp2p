package main

import (
	"fmt"
	"net"
)

type sdwanHandler struct{}

func (*sdwanHandler) handleMessage(ctx *msgContext) error {
	sess, ok := ctx.sess.(*wssSession)
	if !ok {
		return fmt.Errorf("SD-WAN request requires an authenticated websocket")
	}
	head, err := decodeHeader(ctx.msg)
	if err != nil {
		return err
	}
	if head.SubType != MsgSDWANInfoReq {
		return nil
	}
	info := gOptions.SDWAN
	member := false
	for _, node := range info.Nodes {
		if node.Name == sess.node {
			member = true
			break
		}
	}
	if info.Enable == 0 || !member {
		info = SDWANInfo{TunnelNum: 2, Mtu: 1420}
	}
	return sess.write(MsgSDWAN, MsgSDWANInfoRsp, info)
}

func validateSDWAN(info SDWANInfo) error {
	if info.Enable == 0 {
		return nil
	}
	_, subnet, err := net.ParseCIDR(info.Gateway)
	if err != nil {
		return fmt.Errorf("invalid SD-WAN gateway: %w", err)
	}
	if info.Mode != "fullmesh" && info.Mode != "central" {
		return fmt.Errorf("SD-WAN mode must be fullmesh or central")
	}
	if info.TunnelNum < 2 || info.TunnelNum > 8 || info.Mtu < 576 || info.Mtu > 1500 {
		return fmt.Errorf("invalid SD-WAN tunnel count or MTU")
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	for _, node := range info.Nodes {
		if node == nil || len(node.Name) < MinNodeNameLen || names[node.Name] {
			return fmt.Errorf("invalid or duplicate SD-WAN node")
		}
		ip := net.ParseIP(node.IP)
		if ip == nil || !subnet.Contains(ip) || addresses[ip.String()] {
			return fmt.Errorf("invalid or duplicate SD-WAN node IP")
		}
		names[node.Name], addresses[ip.String()] = true, true
	}
	if info.Mode == "central" && !names[info.CentralNode] {
		return fmt.Errorf("SD-WAN central node is not a member")
	}
	return nil
}
