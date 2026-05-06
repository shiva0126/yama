package messaging

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"
)

// Connect opens a NATS connection for the defense plane and returns both the
// base connection and JetStream context.
func Connect(url string) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := nats.Connect(url,
		nats.Name("yama-defense-plane"),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, nil, err
	}

	return nc, js, nil
}

// EnsureDefenseStream creates the JetStream stream if it does not already exist.
func EnsureDefenseStream(js nats.JetStreamContext) error {
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "YAMA_DEFENSE",
		Subjects: []string{
			SubjectSignalsRaw,
			SubjectSignalsNormalized,
			SubjectDetectionsRaw,
			SubjectIncidents,
			SubjectResponsesRequested,
			SubjectResponsesExecuted,
			SubjectEvidenceEvents,
		},
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		Replicas:  1,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		return err
	}

	return nil
}

// PublishJSON is a small helper for emitting structured defense events into the
// JetStream backbone.
func PublishJSON(ctx context.Context, js nats.JetStreamContext, subject string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = js.PublishMsg(&nats.Msg{
		Subject: subject,
		Data:    raw,
	}, nats.Context(ctx))
	return err
}

// StartConsumer creates a durable JetStream consumer and delivers each message
// payload to the supplied callback. Acknowledgement happens only after the
// callback succeeds.
func StartConsumer(js nats.JetStreamContext, subject, durable string, handler func([]byte) error) error {
	_, err := js.Subscribe(subject, func(msg *nats.Msg) {
		if err := handler(msg.Data); err == nil {
			_ = msg.Ack()
		} else {
			_ = msg.Nak()
		}
	}, nats.Durable(durable), nats.ManualAck(), nats.AckExplicit(), nats.DeliverAll(), nats.BindStream("YAMA_DEFENSE"))
	return err
}
