package deliver

import "testing"

// get is a readability shim: the interp.Env contract is (value, ok).
func get(t *testing.T, env *sieveEnv, name string) (string, bool) {
	t.Helper()
	return env.GetEnvironment(name)
}

// TestSieveEnv_SpamItems covers the whole point of the provider: a script can
// read the out-of-band verdict, which never appears in the message and so
// cannot be forged by the sender.
func TestSieveEnv_SpamItems(t *testing.T) {
	env := newSieveEnv(&SpamVerdict{
		IsSpam: true,
		Score:  12.8,
		Headers: map[string]string{
			"X-Spam-Value": "9",
		},
	})

	tests := []struct {
		item string
		want string
	}{
		{"vnd.maildancer.spam-flag", "YES"},
		{"vnd.maildancer.spam-value", "9"},
		{"vnd.maildancer.spam-score", "12.80"},
	}

	for _, tt := range tests {
		t.Run(tt.item, func(t *testing.T) {
			got, ok := get(t, env, tt.item)
			if !ok {
				t.Fatalf("%s reported unsupported, want %q", tt.item, tt.want)
			}
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.item, got, tt.want)
			}
		})
	}
}

// TestSieveEnv_ScannedClean: a scan that ran and found nothing is a real
// verdict and must be readable as one.
func TestSieveEnv_ScannedClean(t *testing.T) {
	env := newSieveEnv(&SpamVerdict{
		IsSpam:  false,
		Score:   -2.5,
		Headers: map[string]string{"X-Spam-Value": "1"},
	})

	if got, ok := get(t, env, "vnd.maildancer.spam-flag"); !ok || got != "NO" {
		t.Errorf("spam-flag = (%q, %v), want (\"NO\", true)", got, ok)
	}
	if got, ok := get(t, env, "vnd.maildancer.spam-value"); !ok || got != "1" {
		t.Errorf("spam-value = (%q, %v), want (\"1\", true)", got, ok)
	}
	if got, ok := get(t, env, "vnd.maildancer.spam-score"); !ok || got != "-2.50" {
		t.Errorf("spam-score = (%q, %v), want (\"-2.50\", true)", got, ok)
	}
}

// TestSieveEnv_NoScanIsUnsupported is the distinction the design doc requires
// delivery-side policy to honor: "no verdict" is not "not spam".
//
// RFC 5183 section 4 makes an unsupported item fail its test unconditionally,
// so a threshold rule simply does not fire when nothing was scanned. Reporting
// ("", true) instead would compare an empty string -- or a zero, once coerced --
// and read as "definitely clean", which is the opposite of the truth.
func TestSieveEnv_NoScanIsUnsupported(t *testing.T) {
	env := newSieveEnv(nil)

	for _, item := range []string{
		"vnd.maildancer.spam-flag",
		"vnd.maildancer.spam-value",
		"vnd.maildancer.spam-score",
	} {
		if got, ok := get(t, env, item); ok {
			t.Errorf("%s = (%q, true) with no scan, want unsupported", item, got)
		}
	}
}

// TestSieveEnv_MissingValueHeaderIsUnsupported: spam-value comes from the
// checker's header set, which an older or non-rspamd checker may not populate.
// Absent means unsupported, not "0" -- 0 is a meaningful value on the RFC 5235
// scale ("not tested"), so inventing it would assert something false.
func TestSieveEnv_MissingValueHeaderIsUnsupported(t *testing.T) {
	env := newSieveEnv(&SpamVerdict{IsSpam: true, Score: 12.8})

	if got, ok := get(t, env, "vnd.maildancer.spam-value"); ok {
		t.Errorf("spam-value = (%q, true) with no X-Spam-Value header, want unsupported", got)
	}
	// The items that do not depend on that header still work.
	if _, ok := get(t, env, "vnd.maildancer.spam-flag"); !ok {
		t.Error("spam-flag should still be available")
	}
}

// TestSieveEnv_StandardItems: RFC 5183 section 4.1 items we can answer.
func TestSieveEnv_StandardItems(t *testing.T) {
	env := newSieveEnv(nil)

	tests := []struct {
		item string
		want string
	}{
		{"name", "maildancer"},
		// RFC 5183: "MDA" for a mail delivery agent. mail-session is where the
		// script runs, after session-manager has dropped to the recipient.
		{"location", "MDA"},
		// "during" -- Sieve runs as part of delivery, not before or after it.
		{"phase", "during"},
	}

	for _, tt := range tests {
		t.Run(tt.item, func(t *testing.T) {
			got, ok := get(t, env, tt.item)
			if !ok {
				t.Fatalf("%s reported unsupported, want %q", tt.item, tt.want)
			}
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.item, got, tt.want)
			}
		})
	}
}

// TestSieveEnv_UnknowableItemsAreUnsupported: mail-session runs
// privilege-dropped, after the SMTP conversation is over, and never saw the
// client. Reporting "" for these would claim we know the remote host was empty.
func TestSieveEnv_UnknowableItemsAreUnsupported(t *testing.T) {
	env := newSieveEnv(nil)

	for _, item := range []string{"remote-host", "remote-ip", "domain"} {
		if got, ok := get(t, env, item); ok {
			t.Errorf("%s = (%q, true), want unsupported", item, got)
		}
	}
}

// TestSieveEnv_UnknownItem: anything we do not define is unsupported.
func TestSieveEnv_UnknownItem(t *testing.T) {
	env := newSieveEnv(nil)
	if got, ok := get(t, env, "vnd.example.nonsense"); ok {
		t.Errorf("unknown item = (%q, true), want unsupported", got)
	}
}

// TestSieveEnv_NameLookupIsCaseInsensitive. go-sieve lowercases the item name
// before calling us, but the provider is exported behavior in its own right and
// RFC 5183 defines the names as case-insensitive, so it must not depend on the
// caller having done that.
func TestSieveEnv_NameLookupIsCaseInsensitive(t *testing.T) {
	env := newSieveEnv(&SpamVerdict{IsSpam: true, Headers: map[string]string{"X-Spam-Value": "9"}})

	for _, item := range []string{
		"VND.MAILDANCER.SPAM-VALUE",
		"Vnd.Maildancer.Spam-Value",
		"NAME",
	} {
		if _, ok := get(t, env, item); !ok {
			t.Errorf("%s reported unsupported; lookup should be case-insensitive", item)
		}
	}
}
