package auth

import (
	"strconv"
	"time"
)

func mustIssueCompat(payloadJSON []byte, secret string) string {
	token, err := IssueTokenJSON(payloadJSON, secret)
	if err != nil {
		panic(err) // fixed compatibility encoders always emit valid JSON
	}
	return token
}

func durationSecondsString(duration time.Duration) string {
	return strconv.FormatInt(int64(duration/time.Second), 10)
}
