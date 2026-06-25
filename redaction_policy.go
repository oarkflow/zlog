package zlog

// RedactionDictionary contains all field names used by compliance presets.
// It is exported so applications can own the policy instead of relying on
// hidden logger internals. Use WithDictionary or Config.RedactionDictionary to
// replace or extend these lists.
type RedactionDictionary struct {
	Secrets []string `json:"secrets"`
	PII     []string `json:"pii"`
	HIPAA   []string `json:"hipaa"`
	PCI     []string `json:"pci"`
}

func (d RedactionDictionary) isZero() bool {
	return len(d.Secrets) == 0 && len(d.PII) == 0 && len(d.HIPAA) == 0 && len(d.PCI) == 0
}

// Merge returns a dictionary with non-empty fields from override appended to base.
func (d RedactionDictionary) Merge(override RedactionDictionary) RedactionDictionary {
	d.Secrets = append(append([]string(nil), d.Secrets...), override.Secrets...)
	d.PII = append(append([]string(nil), d.PII...), override.PII...)
	d.HIPAA = append(append([]string(nil), d.HIPAA...), override.HIPAA...)
	d.PCI = append(append([]string(nil), d.PCI...), override.PCI...)
	return d
}

// DefaultRedactionDictionary returns the package's recommended starter policy.
// These values are not embedded in matcher code; callers can replace the whole
// dictionary or append tenant/domain-specific fields from config.
func DefaultRedactionDictionary() RedactionDictionary {
	return RedactionDictionary{
		Secrets: []string{
			"password*", "passwd*", "pwd", "passphrase*",
			"secret*", "client_secret", "private_key", "private-key", "ssh_key",
			"token*", "access_token", "refresh_token", "id_token", "identity_token",
			"authorization", "cookie", "set-cookie", "session_id", "sid",
			"api_key", "apikey", "api-key", "x-api-key",
			"csrf", "signature", "hmac", "mfa", "otp", "totp",
			"pem", "pin", "certificate", "cert",
		},
		PII: []string{
			"email", "email_address", "phone", "phone_number",
			"first_name", "last_name", "full_name", "person_name",
			"dob", "date_of_birth", "passport", "driver_license", "license_number",
			"ssn", "social_security", "national_id", "address", "street", "postal",
			"ip_address",
		},
		HIPAA: []string{
			"patient", "patient_id", "phi", "mrn", "medical", "medical_record",
			"health", "health_plan", "healthcare", "diagnosis", "prescription",
			"insurance", "member_id", "plan_number", "provider", "hicn", "device_id",
		},
		PCI: []string{
			"pan", "payment_account", "card", "card_number", "credit_card", "cvv", "cvc", "expiry", "expiration",
		},
	}
}

func matchRedactionFields(key, path string, fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	return matchRedactionFieldsName(key, fields) || (path != "" && path != key && matchRedactionFieldsName(path, fields))
}

func matchRedactionFieldsName(name string, fields []string) bool {
	if name == "" {
		return false
	}
	// Full key/path checks are only needed for configured patterns containing
	// separators, for example "x-api-key" or "profile.secret". Plain field
	// patterns are matched token-by-token below.
	for _, f := range fields {
		if redactionPatternHasSep(f) && matchRedactionPattern(name, f) {
			return true
		}
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' || name[i] == '_' || name[i] == '-' || name[i] == '/' || name[i] == ' ' {
			if i > start {
				tok := name[start:i]
				for _, f := range fields {
					if matchRedactionPattern(tok, f) {
						return true
					}
				}
			}
			start = i + 1
		}
	}
	return false
}

func matchRedactionPattern(name, pattern string) bool {
	if name == "" || pattern == "" {
		return false
	}
	pc := lowerASCII(pattern[0])
	nc := lowerASCII(name[0])
	if pc != nc {
		return false
	}
	if pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return prefix == "" || hasPrefixFoldASCII(name, prefix)
	}
	return equalFoldASCII(name, pattern)
}

func redactionPatternHasSep(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', '_', '-', '/', ' ':
			return true
		}
	}
	return false
}

type redactionMatcher struct {
	secrets fieldMatcher
	pii     fieldMatcher
	hipaa   fieldMatcher
	pci     fieldMatcher
}

type fieldMatcher struct {
	plain [256][]string
	sep   [256][]string
}

func newRedactionMatcher(d RedactionDictionary) *redactionMatcher {
	return &redactionMatcher{
		secrets: newFieldMatcher(d.Secrets),
		pii:     newFieldMatcher(d.PII),
		hipaa:   newFieldMatcher(d.HIPAA),
		pci:     newFieldMatcher(d.PCI),
	}
}

func newFieldMatcher(fields []string) fieldMatcher {
	var m fieldMatcher
	for _, f := range fields {
		if f == "" {
			continue
		}
		c := lowerASCII(f[0])
		if redactionPatternHasSep(f) {
			m.sep[c] = append(m.sep[c], f)
		} else {
			m.plain[c] = append(m.plain[c], f)
		}
	}
	return m
}

func (m *fieldMatcher) match(key, path string) bool {
	if m == nil {
		return false
	}
	return m.matchName(key) || (path != "" && path != key && m.matchName(path))
}

func (m *fieldMatcher) matchName(name string) bool {
	if name == "" {
		return false
	}
	if m.matchFullName(name) {
		return true
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' || name[i] == '_' || name[i] == '-' || name[i] == '/' || name[i] == ' ' {
			if i > start {
				tok := name[start:i]
				bucket := m.plain[lowerASCII(tok[0])]
				for _, f := range bucket {
					if matchRedactionPattern(tok, f) {
						return true
					}
				}
			}
			start = i + 1
		}
	}
	return false
}

func (m *fieldMatcher) matchFullName(name string) bool {
	bucket := m.sep[lowerASCII(name[0])]
	for _, f := range bucket {
		if matchRedactionPattern(name, f) {
			return true
		}
	}
	return false
}
