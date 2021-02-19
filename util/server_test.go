// +build ignore

package mdns

import (
	"testing"

	registry "github.com/unistack-org/micro/v3/register"
)

var (
	svc1 = &registry.Service{
		Name:    "foo",
		Version: "latest",
		Nodes: []*registry.Node{
			&registry.Node{
				Id:      "1",
				Address: "127.0.0.1",
			},
		},
	}
)

func TestServer_StartStop(t *testing.T) {
	//s := makeService(t)
	srv, err := NewServer(&Config{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if err = srv.Shutdown(); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestServer_Lookup(t *testing.T) {
	srv1, err := NewServer(&Config{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer srv1.Shutdown()
	/*
		srv2, err := NewServer(&Config{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer srv2.Shutdown()
	*/
	if err = srv1.Register(svc1); err != nil {
		t.Fatalf("err: %v", err)
	}
	/*
		select {}
		services, err := srv2.GetService("foo")
		if err != nil {
			t.Fatalf("err: %v", err)
		} else if len(services) == 0 {
			t.Fatalf("empty service")
		}

		for _, svc := range services {
			fmt.Printf("%#+v\n", svc)
		}
	*/
	select {}
}
