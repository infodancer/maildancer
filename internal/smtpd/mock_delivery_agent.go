package smtpd

import (
	"context"
	"errors"
	"io"

	"github.com/infodancer/maildancer/msgstore"
)

// MockDeliveryAgent is a mock implementation of the msgstore.DeliveryAgent interface for testing.
type MockDeliveryAgent struct {
	// LastEnvelope stores the envelope of the last delivered message.
	LastEnvelope *msgstore.Envelope
	// LastMessageData stores the raw content of the last delivered message.
	LastMessageData []byte
	// ShouldError, if true, causes the Deliver method to return an error.
	ShouldError bool
	// ErrorToReturn is the error to return when ShouldError is true.
	ErrorToReturn error
}

// Deliver captures the envelope and message data for inspection in tests.
func (m *MockDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if m.ShouldError {
		if m.ErrorToReturn != nil {
			return m.ErrorToReturn
		}
		return errors.New("mock delivery agent error")
	}

	m.LastEnvelope = &envelope
	data, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	m.LastMessageData = data

	return nil
}

// Reset clears the captured data from the last delivery.
func (m *MockDeliveryAgent) Reset() {
	m.LastEnvelope = nil
	m.LastMessageData = nil
	m.ShouldError = false
	m.ErrorToReturn = nil
}
