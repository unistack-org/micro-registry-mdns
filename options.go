// Package mdns provides a multicast dns registry
package mdns

import (
	"context"

	"github.com/unistack-org/micro/v3/register"
)

// Domain sets the mdnsDomain
func Domain(d string) register.Option {
	return func(o *register.Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		o.Context = context.WithValue(o.Context, "mdns.domain", d)
	}
}
