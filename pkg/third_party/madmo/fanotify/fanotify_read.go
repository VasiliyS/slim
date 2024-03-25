//go:build linux && !s390x

package fanotify

import (
	"encoding/binary"
)

// Get an event from the fanotify handle
func (nd *NotifyFD) readMetaData(ev *eventMetadata) error {

	err := binary.Read(nd.r, binary.LittleEndian, ev)
	if err != nil {
		return err
	}

	return nil
}
