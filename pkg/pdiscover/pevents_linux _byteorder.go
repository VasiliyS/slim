//go:build !s390x && !darwin

package pdiscover

import (
	"encoding/binary"
)

var (
	byteOrder = binary.LittleEndian
)
