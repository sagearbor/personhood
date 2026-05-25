//go:build !twilio

package sms

import (
	"context"
	"testing"
)

func TestTwilioSenderEnabled_FalseWithoutTag(t *testing.T) {
	if TwilioSenderEnabled() {
		t.Error("TwilioSenderEnabled must be false without the twilio tag")
	}
}

func TestNewTwilioSender_ErrorsWithoutTag(t *testing.T) {
	if _, err := NewTwilioSender("AC", "tok", "+1"); err == nil {
		t.Error("NewTwilioSender must error without the twilio tag")
	}
}

func TestTwilioSender_Send_ErrorsWithoutTag(t *testing.T) {
	s := &TwilioSender{}
	if err := s.Send(context.Background(), "+1", "body"); err == nil {
		t.Error("Send must error without the twilio tag")
	}
}
