//go:build !sendgrid

package email

import (
	"context"
	"testing"
)

func TestSendGridSenderEnabled_FalseWithoutTag(t *testing.T) {
	if SendGridSenderEnabled() {
		t.Error("SendGridSenderEnabled must be false without the sendgrid tag")
	}
}

func TestNewSendGridSender_ErrorsWithoutTag(t *testing.T) {
	if _, err := NewSendGridSender("k", "from@x.com", "Name"); err == nil {
		t.Error("NewSendGridSender must error without the sendgrid tag")
	}
}

func TestSendGridSender_Send_ErrorsWithoutTag(t *testing.T) {
	s := &SendGridSender{}
	if err := s.Send(context.Background(), "alice@example.com", "subj", "https://x"); err == nil {
		t.Error("Send must error without the sendgrid tag")
	}
}
