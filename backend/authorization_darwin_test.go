package main

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"testing"
)

func TestConsoleAuthorizationRecheckedForExistingConnection(t *testing.T) {
	uid := uint32(501)
	var lookupErr error
	interceptor := authorizeConsoleRPC(func() (uint32, error) { return uid, lookupErr })
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: localIdentity{uid: 501, pid: 123}})
	calls := 0
	handler := func(context.Context, interface{}) (interface{}, error) { calls++; return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/VPNControl/Start"}
	if _, err := interceptor(ctx, nil, info, handler); err != nil {
		t.Fatal(err)
	}
	uid = 502
	if _, err := interceptor(ctx, nil, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("old console user accepted: %v", err)
	}
	uid = 0
	if _, err := interceptor(ctx, nil, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("login window accepted: %v", err)
	}
	uid = 501
	lookupErr = errors.New("console unavailable")
	if _, err := interceptor(ctx, nil, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("failed console lookup accepted: %v", err)
	}
	if _, err := interceptor(context.Background(), nil, info, handler); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing peer accepted: %v", err)
	}
	if calls != 1 {
		t.Fatalf("unauthorized handler calls: %d", calls)
	}
}
