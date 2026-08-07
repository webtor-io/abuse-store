package services

import (
	"testing"
)

// The pattern must match a whole infohash and nothing else. Unanchored, it
// accepted any string with five hex characters somewhere in it, which is how
// magnet URIs and web links ended up stored verbatim as stoplist keys.
func TestInfohashValidation(t *testing.T) {
	const valid = "c9e15763f722f23e98a29decdfae341b98d53056"
	cases := []struct {
		name string
		in   string
		want string // normalized form, "" means it must be refused
	}{
		{"plain", valid, valid},
		{"upper case is normalized, not refused", "C9E15763F722F23E98A29DECDFAE341B98D53056", valid},
		{"surrounding whitespace", "  " + valid + "\n", valid},
		{"magnet uri", "magnet:?xt=urn:btih:" + valid + "&dn=x", ""},
		{"web link", "https://webtor.io/" + valid, ""},
		{"junk with hex inside", "ZZZZ!!!abcde", ""},
		{"sql-looking payload", "'; DROP TABLE abuse;--abcde", ""},
		{"too short", "c9e157", ""},
		{"too long", valid + "00", ""},
		{"non-hex letters", "z9e15763f722f23e98a29decdfae341b98d53056", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeInfohash(tc.in)
			ok := infohashRe.MatchString(got)
			if tc.want == "" {
				if ok {
					t.Fatalf("%q was accepted as %q, want refused", tc.in, got)
				}
				return
			}
			if !ok {
				t.Fatalf("%q was refused, want accepted", tc.in)
			}
			if got != tc.want {
				t.Fatalf("normalized to %q, want %q", got, tc.want)
			}
		})
	}
}
