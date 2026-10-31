package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openp2p-cn/totp"
)

type pushHandler struct {
}

type pushPair struct{ from, to uint64 }

func (mgr *sessionMgr) grantPush(from, to uint64) {
	expires := time.Now().Add(time.Minute)
	mgr.pushPermission.Store(pushPair{from, to}, expires)
	mgr.pushPermission.Store(pushPair{to, from}, expires)
}

func (h *pushHandler) handleMessage(ctx *msgContext) error {
	if len(ctx.msg) < openP2PHeaderSize+PushHeaderSize {
		return errors.New("short push message")
	}
	head := openP2PHeader{}
	err := binary.Read(bytes.NewReader(ctx.msg[:openP2PHeaderSize]), binary.LittleEndian, &head)
	if err != nil {
		return err
	}
	pushHead := PushHeader{}
	err = binary.Read(bytes.NewReader(ctx.msg[openP2PHeaderSize:openP2PHeaderSize+PushHeaderSize]), binary.LittleEndian, &pushHead)
	if err != nil {
		return err
	}
	fromSess, ok := ctx.sess.(*wssSession)
	if !ok {
		gLog.Println(LvERROR, "interface conversion error")
		return errors.New("interface conversion error")
	}
	if pushHead.From != fromSess.nodeID {
		return errors.New("push sender does not match authenticated node")
	}
	gLog.Printf(LvDEBUG, "%d push to %d", pushHead.From, pushHead.To)
	if !isSupportMsg(head.SubType) {
		rsp := PushRsp{Error: 1, Detail: "push denied: unSupported msg "}
		fromSess.write(head.MainType, MsgPushRsp, rsp)
		return errors.New("push denied")
	}
	gWSSessionMgr.allSessionsMtx.Lock()
	toSess, ok := gWSSessionMgr.allSessions[pushHead.To]
	gWSSessionMgr.allSessionsMtx.Unlock()
	if !ok {
		gLog.Printf(LvERROR, "%d push to %d error: peer offline", pushHead.From, pushHead.To)
		rsp := PushRsp{Error: 1, Detail: "peer offline"}
		fromSess.write(head.MainType, MsgPushRsp, rsp)
		return errors.New("peer offline")
	}
	if head.SubType == MsgPushConnectReq {
		// verify user/password
		req := PushConnectReq{}
		err := json.Unmarshal(ctx.msg[openP2PHeaderSize+PushHeaderSize:], &req)
		if err != nil {
			gLog.Printf(LvERROR, "wrong MsgPushConnectReq:%s", err)
			return err
		}
		gLog.Printf(LvINFO, "%s is connecting to %s...", req.From, toSess.node)
		t := totp.TOTP{Step: totp.RelayTOTPStep}
		if req.From != fromSess.node || !(t.Verify(req.Token, toSess.token, time.Now().Unix()) || (toSess.token == req.FromToken)) {
			gLog.Printf(LvERROR, "%s --- %s MsgPushConnectReq push denied", req.From, toSess.node)
			rsp := PushRsp{Error: 1, Detail: "MsgPushConnectReq push denied"}
			fromSess.write(head.MainType, MsgPushRsp, rsp)
			return errors.New("push denied")
		}
		// cache push permission 60s
		gWSSessionMgr.grantPush(pushHead.From, pushHead.To)
		// TODO: clear cache
	} else if isByPassMsg(head.SubType) {
		if fromSess.user != toSess.user {
			return errors.New("application state belongs to another user")
		}
		gLog.Println(LvDEBUG, "sync app key")
	} else {
		// verify push permission
		// verify from as key
		pair := pushPair{pushHead.From, pushHead.To}
		i, ok := gWSSessionMgr.pushPermission.Load(pair)
		granted := false
		if ok {
			if i.(time.Time).After(time.Now()) {
				granted = true
			} else {
				gWSSessionMgr.pushPermission.Delete(pair)
			}
		}
		if !granted {
			gLog.Printf(LvERROR, "%d --- %d push denied", pushHead.From, pushHead.To)
			rsp := PushRsp{Error: 1, Detail: "push denied"}
			fromSess.write(head.MainType, MsgPushRsp, rsp)
			return errors.New("push denied")
		}
	}
	toSess.writeBuff(ctx.msg)
	rsp := PushRsp{Error: 0, Detail: fmt.Sprintf("push msgType %d,%d to %d ok", head.MainType, head.SubType, pushHead.From)}
	fromSess.write(head.MainType, MsgPushRsp, rsp)
	return nil
}

func isSupportMsg(msgType uint16) bool {
	if msgType == MsgPushRsp ||
		msgType == MsgPushConnectReq ||
		msgType == MsgPushConnectRsp ||
		msgType == MsgPushHandshakeStart ||
		msgType == MsgPushAddRelayTunnelReq ||
		msgType == MsgPushAddRelayTunnelRsp ||
		msgType == MsgPushUnderlayConnect ||
		msgType == MsgPushAPPKey ||
		msgType == MsgPushServerSideSaveMemApp {
		return true
	}
	return false
}

func isByPassMsg(msgType uint16) bool {
	return msgType == MsgPushAPPKey || msgType == MsgPushServerSideSaveMemApp
}
