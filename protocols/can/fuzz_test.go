package can

import "testing"

func FuzzValidateResponse(f *testing.F) {
	f.Add([]byte("V1013\r"))
	f.Add([]byte("NA1B2\r"))
	f.Add([]byte("\r"))
	f.Add([]byte("\a"))
	f.Add([]byte{0x00, 0x01, 0x80, 0xFF})
	f.Add([]byte{})
	f.Add([]byte("Hello World\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := validateResponse(data)
		if result.Confidence < 0 || result.Confidence > 1.0 {
			t.Errorf("confidence out of range: %f", result.Confidence)
		}
		if result.Matched && result.Confidence == 0 {
			t.Error("matched but confidence is 0")
		}
	})
}
