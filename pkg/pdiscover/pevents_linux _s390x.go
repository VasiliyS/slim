// hacked up code from CloudFoundry

// Go interface to the Linux netlink process connector.
// See Documentation/connector/connector.txt in the linux kernel source tree.
package pdiscover

import (
	"encoding/binary"
)

var (
	byteOrder = binary.BigEndian
)
