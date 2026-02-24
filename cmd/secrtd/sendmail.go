package main

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"text/template"

	"github.com/wneessen/go-mail"
)

type MailRequest struct {
	To      string
	Subject string
	Body    string
	Values  any
}

var MailChannel = make(chan *MailRequest, 16)

func startMailPoller(wg *sync.WaitGroup, replicas int) {
	for range replicas {
		go mailPoller(wg)
	}
}

func stopMailPoller() {
	close(MailChannel)
}

func mailPoller(wg *sync.WaitGroup) {
	wg.Add(1)
	for mailRequest := range MailChannel {
		if err := sendmail(mailRequest.To, mailRequest.Subject, mailRequest.Body, mailRequest.Values); err != nil {
			log.Println("unable to send activation email:", err)
		}
	}
	wg.Done()
}

func QueueMail(to string, subject, body string, values any) {
	MailChannel <- &MailRequest{
		To:      to,
		Subject: subject,
		Body:    body,
		Values:  values,
	}
}

// WARNING: don't call sendmail directly. Call QueueMail instead.
func sendmail(to string, subject string, msg string, values any) error {

	if Config.SMTPDisable {
		return nil
	}

	tmpl, err := template.New("email").Parse(msg)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, values)
	if err != nil {
		return err
	}

	mailBody := buf.String()

	message := mail.NewMsg()
	if err := message.From("welcome@hello.secrt.io"); err != nil {
		return fmt.Errorf("failed to set FROM address: %w", err)
	}

	if err := message.To(to); err != nil {
		log.Fatalf("failed to set TO address: %s", err)
	}

	message.Subject(subject)
	message.SetBodyString(mail.TypeTextPlain, mailBody)

	// Deliver the mails via SMTP
	client, err := mail.NewClient(Config.SMTPServer,
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover), mail.WithTLSPortPolicy(mail.TLSMandatory),
		mail.WithUsername(Config.SMTPUsername), mail.WithPassword(Config.SMTPPassword),
	)

	message.SetGenHeader(mail.Header(Config.SMTPHeaderKey), Config.SMTPHeaderValue)

	if err != nil {
		log.Fatalf("failed to create new mail delivery client: %s", err)
	}

	if err := client.DialAndSend(message); err != nil {
		log.Fatalf("failed to deliver mail: %s", err)
	}

	log.Printf("Test mail successfully delivered.")

	return nil
}
