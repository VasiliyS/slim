//go:build linux

package fanotify

import (
	"encoding/binary"
)

// Get an event from the fanotify handle
func (nd *NotifyFD) readMetaData(ev *eventMetadata) error {

	err := binary.Read(nd.r, binary.BigEndian, ev)
	if err != nil {
		return err
	}

	return nil
}
