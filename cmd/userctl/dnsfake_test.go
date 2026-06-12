package main

import (
	"context"
	"errors"
	"net"
)

// fakeResolver serves canned DNS answers for the domain dns tests.
type fakeResolver struct {
	hosts map[string][]string
	mxs   map[string][]*net.MX
	txts  map[string][]string
	ptrs  map[string][]string
}

var errFakeNXDomain = errors.New("no such host")

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if v, ok := f.hosts[host]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := f.mxs[name]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txts[name]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptrs[addr]; ok {
		return v, nil
	}
	return nil, errFakeNXDomain
}
