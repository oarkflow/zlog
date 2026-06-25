package zlog

func hasSensitiveKeyStart(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		switch c {
		case 'p', 's', 't', 'a', 'c', 'x', 'i', 'h', 'm', 'o':
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func containsFoldASCII(s, sub string) bool {
	if sub == "" {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	first := sub[0]
	if first >= 'A' && first <= 'Z' {
		first += 'a' - 'A'
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == first && equalFoldASCII(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func hasPrefixFoldASCII(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return equalFoldASCII(s[:len(prefix)], prefix)
}

func containsFoldASCIIWhole(s, sub string) bool { return containsFoldASCII(s, sub) }

func trimSpaceBounds(s string) (int, int) {
	lo, hi := 0, len(s)
	for lo < hi {
		switch s[lo] {
		case ' ', '\t', '\n', '\r':
			lo++
		default:
			goto endLo
		}
	}
endLo:
	for hi > lo {
		switch s[hi-1] {
		case ' ', '\t', '\n', '\r':
			hi--
		default:
			goto endHi
		}
	}
endHi:
	return lo, hi
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
