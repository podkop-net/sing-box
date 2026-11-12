package domainset

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing-box/common/cidrset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

// ReadSource reads a rule set of the source format, JSON, into what
// json.UnmarshalExtended[option.PlainRuleSetCompat] reads of it, in one pass and without
// a copy of the names where it can. The rules differ in one way: the names of a rule of
// the default type (domain, domain_suffix) come as their trie (DomainSet), and its CIDR
// lists (source_ip_cidr, ip_cidr) as their sets (SourceIPRanges, IPRanges), not as lists
// of strings; the trie and the sets, and what they tell of themselves, are what
// route/rule builds of those lists.
//
// What it reads so is JSON of a strict shape: the object of the rule set with "version"
// (a digit) and "rules", nothing around it but white space. In a rule it reads the lists of
// strings itself (domain, domain_suffix, domain_keyword, domain_regex, source_ip_cidr,
// ip_cidr, each a string, an array of strings or null), and hands the other fields to
// sing-box as a small object. Anything else (comments, a logical rule, a field written in
// other letters, a key twice, a value of another shape) goes to sing-box: a rule alone,
// when the shape of the set is as above, or the whole text. So does any error: the error
// is then sing-box's own.
func ReadSource(content []byte) (option.PlainRuleSetCompat, error) {
	return ReadSourceContext(context.Background(), content)
}

// ReadSourceContext is ReadSource that stops with the error of ctx once it is done: a rule
// set closed while it reads a big list does not read it to the end. The decoding of
// sing-box, for a text of another shape, is not stopped.
func ReadSourceContext(ctx context.Context, content []byte) (option.PlainRuleSetCompat, error) {
	compat, ok, err := readSource(ctx, content)
	if err != nil {
		return compat, err
	}
	if ok {
		return compat, nil
	}
	return json.UnmarshalExtended[option.PlainRuleSetCompat](content)
}

// the lists of strings of a default rule read here, in the order of their bit in a mask
const (
	fieldDomain = iota
	fieldDomainSuffix
	fieldDomainKeyword
	fieldDomainRegex
	fieldSourceIPCIDR
	fieldIPCIDR
	fieldCount
)

var (
	fieldNames = [fieldCount]string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "source_ip_cidr", "ip_cidr"}
	// the keys whose other spellings are sing-box's to read
	foldNames = append(fieldNames[:], "type")
)

// ReadSourceAddresses is ReadSource for those who want the addresses of a rule set and the
// shape of its rules, not its matcher: the names of domain and domain_suffix are counted,
// not gathered, and a rule keeps the first three of each as its lists (Domain,
// DomainSuffix) in place of the trie. Everything else is read as ReadSource reads it.
func ReadSourceAddresses(content []byte) (option.PlainRuleSetCompat, error) {
	compat, ok := readSourceText(&reader{text: content, ctx: context.Background(), addresses: true})
	if ok {
		return compat, nil
	}
	return json.UnmarshalExtended[option.PlainRuleSetCompat](content)
}

// reader is the text of a rule set and where it is read. It stops once ctx is done, and
// err tells why. addresses: the names of domains are not gathered (ReadSourceAddresses).
type reader struct {
	text      []byte
	at        int
	ctx       context.Context
	items     int
	err       error
	addresses bool
}

// stopped tells, every stopEvery items, whether the reading is to stop.
func (r *reader) stopped() bool {
	r.items++
	if r.items&stopEvery == 0 && r.ctx.Err() != nil {
		r.err = r.ctx.Err()
	}
	return r.err != nil
}

func readSource(ctx context.Context, text []byte) (option.PlainRuleSetCompat, bool, error) {
	compat, ok := readSourceText(&reader{text: text, ctx: ctx})
	return compat, ok, ctx.Err()
}

func readSourceText(r *reader) (option.PlainRuleSetCompat, bool) {
	var compat option.PlainRuleSetCompat
	text := r.text
	r.space()
	begin := r.at
	if !r.take('{') {
		return compat, false
	}
	var (
		haveVersion, haveRules bool
		rules                  []option.HeadlessRule
		empty                  = true
	)
	r.space()
	if !r.take('}') {
		for {
			key, plain, ok := r.key()
			if !ok || !plain {
				return compat, false
			}
			switch key {
			case "version":
				if haveVersion {
					return compat, false
				}
				haveVersion = true
				compat.Version, ok = r.version()
			case "rules":
				if haveRules {
					return compat, false
				}
				haveRules = true
				rules, empty, ok = r.rules()
			default:
				// any other key, of other letters too, is sing-box's to tell
				return compat, false
			}
			if !ok {
				return compat, false
			}
			r.space()
			if r.take(',') {
				r.space()
				continue
			}
			if r.take('}') {
				break
			}
			return compat, false
		}
	}
	end := r.at
	r.space()
	if r.at != len(text) || !haveVersion {
		return compat, false
	}
	// rules that are all empty (no rule, or rules whose values are all empty arrays and
	// objects) are dropped by badjson before sing-box reads them: there are none
	if !empty {
		compat.Options.Rules = rules
	}
	compat.RawMessage = text[begin:end]
	return compat, true
}

// version reads the version of the rule set: one digit of a version sing-box knows.
func (r *reader) version() (uint8, bool) {
	if r.at+1 >= len(r.text) {
		return 0, false
	}
	digit := r.text[r.at]
	if digit < '1' || digit > '0'+C.RuleSetVersionCurrent {
		return 0, false
	}
	switch r.text[r.at+1] {
	case ' ', '\t', '\n', '\r', ',', '}':
	default:
		return 0, false
	}
	r.at++
	return digit - '0', true
}

// rules reads the array of rules, and whether every rule is empty as badjson sees it.
func (r *reader) rules() ([]option.HeadlessRule, bool, bool) {
	if !r.take('[') {
		return nil, false, false
	}
	var rules []option.HeadlessRule
	empty := true
	r.space()
	if r.take(']') {
		return nil, true, true
	}
	for {
		rule, ruleEmpty, ok := r.rule()
		if !ok {
			return nil, false, false
		}
		rules = append(rules, rule)
		empty = empty && ruleEmpty
		r.space()
		if r.take(',') {
			r.space()
			continue
		}
		if r.take(']') {
			return rules, empty, true
		}
		return nil, false, false
	}
}

// rule reads a rule: the lists of strings of a default rule here, the rest by sing-box.
// It also tells whether badjson takes the rule for empty.
func (r *reader) rule() (option.HeadlessRule, bool, bool) {
	var rule option.HeadlessRule
	begin := r.at
	if !r.take('{') {
		return rule, false, false
	}
	var (
		// the rule goes to sing-box whole
		whole bool
		// the fields read here, and the ones of them that are not empty arrays
		seen, full uint
		lists      [fieldCount][]string
		names      *Collector
		// the first names of domain and domain_suffix, and how many there are
		first  [2][]string
		counts [2]int
		// the ranges of source_ip_cidr and ip_cidr, their first items, how many there are
		cidrs      [2]cidrset.Builder
		cidrFirst  [2][]string
		cidrCounts [2]int
		// the other members, as their text
		rest [][]byte
	)
	r.space()
	if !r.take('}') {
		for {
			memberStart := r.at
			key, plain, ok := r.key()
			if !ok {
				return rule, false, false
			}
			valueStart := r.at
			field := fieldIndex(key)
			switch {
			case whole:
			case !plain:
				whole = true
			case field >= 0:
				if seen&(1<<field) != 0 {
					// a key twice: badjson keeps the last value
					whole = true
					break
				}
				seen |= 1 << field
				var count int
				if field == fieldDomain || field == fieldDomainSuffix {
					side := field - fieldDomain
					if r.addresses {
						count, ok = r.firstNames(&first[side])
					} else {
						if names == nil {
							names = NewCollectorContext(r.ctx, r.text)
						}
						count, ok = r.names(names, field == fieldDomainSuffix, &first[side])
					}
					counts[side] = count
				} else if field == fieldSourceIPCIDR || field == fieldIPCIDR {
					side := field - fieldSourceIPCIDR
					count, ok = r.cidrs(&cidrs[side], &cidrFirst[side])
					cidrCounts[side] = count
				} else {
					lists[field], ok = r.strings()
					count = len(lists[field])
				}
				if !ok {
					// a value of another shape
					whole = true
					r.at = valueStart
					break
				}
				if count > 0 || r.text[valueStart] != '[' {
					full |= 1 << field
				}
			case foldsTo(key):
				// "Domain", "TYPE": decoding matches fields in any letters
				whole = true
			case key == "type":
				if !r.defaultType() {
					whole = true
				}
				r.at = valueStart
			}
			if whole || field < 0 {
				if !r.skipValue() || r.at == valueStart {
					return rule, false, false
				}
				if !whole {
					rest = append(rest, r.text[memberStart:r.at])
				}
			}
			r.space()
			if r.take(',') {
				r.space()
				continue
			}
			if r.take('}') {
				break
			}
			return rule, false, false
		}
	}
	if whole {
		rule, empty, err := sourceRule(r.text[begin:r.at])
		return rule, empty, err == nil
	}
	restEmpty := true
	if len(rest) == 0 {
		rule.Type = C.RuleTypeDefault
	} else {
		var err error
		rule, restEmpty, err = sourceRule(append(append([]byte{'{'}, bytes.Join(rest, []byte{','})...), '}'))
		if err != nil || rule.Type != C.RuleTypeDefault {
			return rule, false, false
		}
	}
	fields := &rule.DefaultOptions
	fields.DomainKeyword = badoption.Listable[string](lists[fieldDomainKeyword])
	fields.DomainRegex = badoption.Listable[string](lists[fieldDomainRegex])
	if cidrCounts[0] > 0 {
		fields.SourceIPRanges = cidrs[0].Set(cidrset.Describe(true, cidrFirst[0], cidrCounts[0]))
	}
	if cidrCounts[1] > 0 {
		fields.IPRanges = cidrs[1].Set(cidrset.Describe(false, cidrFirst[1], cidrCounts[1]))
	}
	if names != nil && names.Len() > 0 {
		set, err := names.Set(Describe(first[0], counts[0], first[1], counts[1]))
		if err != nil {
			return rule, false, false
		}
		fields.DomainSet = set
	}
	if r.addresses {
		if counts[0] > 0 {
			fields.Domain = first[0]
		}
		if counts[1] > 0 {
			fields.DomainSuffix = first[1]
		}
	}
	return rule, full == 0 && restEmpty, true
}

// sourceRule reads a rule as sing-box reads one of the rules of a set: badjson takes the
// rule apart, writes it again without its empty values, and the rule reads that. It also
// tells whether badjson takes the rule for empty.
func sourceRule(text []byte) (option.HeadlessRule, bool, error) {
	var rule option.HeadlessRule
	var object badjson.JSONObject
	err := object.UnmarshalJSONContext(context.Background(), text)
	if err != nil {
		return rule, false, err
	}
	written, err := object.MarshalJSONContext(context.Background())
	if err != nil {
		return rule, false, err
	}
	err = rule.UnmarshalJSON(written)
	return rule, object.IsEmpty(), err
}

func fieldIndex(key string) int {
	for index, name := range fieldNames {
		if key == name {
			return index
		}
	}
	return -1
}

// foldsTo tells a key that is not one of the fields read here, nor "type", but which the
// decoding of sing-box matches with one of them, as it matches keys in any letters.
func foldsTo(key string) bool {
	for _, name := range foldNames {
		if key != name && strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// defaultType tells that the value of "type" is "default" or "": a default rule, whose
// type sing-box reads with the rest.
func (r *reader) defaultType() bool {
	start, end, plain, ok := r.str()
	if !ok || !plain {
		return false
	}
	value := string(r.text[start:end])
	return value == "" || value == C.RuleTypeDefault
}

// names reads a value of domain or domain_suffix into the collector: a string, an array
// of strings or null. It tells how many names it read, and keeps the first three of them
// for the description of the rule. An empty name is route/rule's to refuse: the rule goes
// to sing-box.
func (r *reader) names(names *Collector, suffix bool, first *[]string) (int, bool) {
	names.Grow(r.countStrings())
	count := 0
	ok := r.each(func(start int, end int, plain bool) bool {
		if start == end {
			return false
		}
		count++
		var err error
		var name string
		if plain {
			err = names.Add(start, end, suffix)
		} else if text, unescaped := r.unescaped(start, end); unescaped {
			err = names.AddBytes(text, suffix)
		} else {
			var ok bool
			name, ok = r.unquote(start, end)
			if !ok || name == "" {
				return false
			}
			err = names.AddString(name, suffix)
		}
		if len(*first) < 3 {
			if name == "" {
				name = string(r.text[start:end])
			}
			*first = append(*first, name)
		}
		return err == nil
	})
	return count, ok
}

// firstNames reads a value of domain or domain_suffix without gathering it: how many names
// there are, and the first three of them. An empty name is route/rule's to refuse, as in
// names.
func (r *reader) firstNames(first *[]string) (int, bool) {
	count := 0
	ok := r.each(func(start int, end int, plain bool) bool {
		if start == end {
			return false
		}
		count++
		if len(*first) >= 3 {
			return true
		}
		name := string(r.text[start:end])
		if !plain {
			var ok bool
			name, ok = r.unquote(start, end)
			if !ok || name == "" {
				return false
			}
		}
		*first = append(*first, name)
		return true
	})
	return count, ok
}

// cidrs reads a value of source_ip_cidr or ip_cidr into the builder: a string, an array of
// strings or null. A canonical IPv4 prefix is read from its text, any other by netip as
// NewIPCIDRItem reads it; one netip refuses is NewIPCIDRItem's to tell: the rule goes to
// sing-box. It tells how many items it read, and keeps the first three of them for the
// description of the rule.
func (r *reader) cidrs(builder *cidrset.Builder, first *[]string) (int, bool) {
	builder.Grow(r.countStrings())
	count := 0
	ok := r.each(func(start int, end int, plain bool) bool {
		count++
		var text string
		if plain {
			if from, to, ok := cidrset.Parse4(r.text[start:end]); ok {
				builder.Add4(from, to)
				if len(*first) < 3 {
					*first = append(*first, string(r.text[start:end]))
				}
				return true
			}
			text = string(r.text[start:end])
		} else {
			var ok bool
			text, ok = r.unquote(start, end)
			if !ok {
				return false
			}
		}
		if len(*first) < 3 {
			*first = append(*first, text)
		}
		if prefix, err := netip.ParsePrefix(text); err == nil {
			return builder.AddPrefix(prefix)
		}
		if address, err := netip.ParseAddr(text); err == nil {
			return builder.AddAddr(address)
		}
		return false
	})
	return count, ok
}

// strings reads a value of one of the other lists: a string, an array of strings or null.
func (r *reader) strings() ([]string, bool) {
	var list []string
	ok := r.each(func(start int, end int, plain bool) bool {
		if plain {
			list = append(list, string(r.text[start:end]))
			return true
		}
		if text, ok := r.unescaped(start, end); ok {
			list = append(list, string(text))
			return true
		}
		value, ok := r.unquote(start, end)
		list = append(list, value)
		return ok
	})
	return list, ok
}

// each reads a string, an array of strings or null, and hands each string to take: where
// its text is, and whether that text is the string as it is (ASCII, no escape).
func (r *reader) each(take func(start int, end int, plain bool) bool) bool {
	if r.at >= len(r.text) {
		return false
	}
	switch r.text[r.at] {
	case '"':
		start, end, plain, ok := r.str()
		return ok && take(start, end, plain)
	case 'n':
		if bytes.HasPrefix(r.text[r.at:], []byte("null")) {
			r.at += 4
			return true
		}
		return false
	case '[':
		r.at++
		r.space()
		if r.take(']') {
			return true
		}
		for {
			start, end, plain, ok := r.str()
			if !ok || r.stopped() || !take(start, end, plain) {
				return false
			}
			r.space()
			if r.take(',') {
				r.space()
				continue
			}
			return r.take(']')
		}
	}
	return false
}

// countStrings counts the strings of the array the reader is at, without reading it: a
// list is gathered into room made once. Anything else counts none.
func (r *reader) countStrings() int {
	if r.at >= len(r.text) || r.text[r.at] != '[' {
		return 0
	}
	count := 0
	for index := r.at + 1; index < len(r.text); index++ {
		switch r.text[index] {
		case '"':
			count++
			for index++; index < len(r.text) && r.text[index] != '"'; index++ {
				if r.text[index] == '\\' {
					index++
				}
			}
		case ']':
			return count
		case '[', '{':
			return 0
		}
	}
	return 0
}

// unescaped is the text of a string that has no escape and is valid UTF-8: the string
// sing-box reads of it, as it is.
func (r *reader) unescaped(start int, end int) ([]byte, bool) {
	text := r.text[start:end]
	return text, bytes.IndexByte(text, '\\') < 0 && utf8.Valid(text)
}

// unquote is the string sing-box reads of the text of a string between its quotes:
// escapes undone, bytes that are not UTF-8 replaced by U+FFFD.
func (r *reader) unquote(start int, end int) (string, bool) {
	var value string
	err := json.Unmarshal(r.text[start-1:end+1], &value)
	return value, err == nil
}

// key reads a key and the colon after it. It tells whether the key is as it is written
// (ASCII, no escape); one that is not is read only to be skipped.
func (r *reader) key() (string, bool, bool) {
	start, end, plain, ok := r.str()
	if !ok {
		return "", false, false
	}
	r.space()
	if !r.take(':') {
		return "", false, false
	}
	r.space()
	return string(r.text[start:end]), plain, true
}

// str reads a string: where its text is between the quotes, and whether that text is the
// string as it is (ASCII, no escape). A string with a control character is no JSON.
func (r *reader) str() (int, int, bool, bool) {
	if r.at >= len(r.text) || r.text[r.at] != '"' {
		return 0, 0, false, false
	}
	start := r.at + 1
	plain := true
	for index := start; index < len(r.text); index++ {
		character := r.text[index]
		switch {
		case character == '"':
			r.at = index + 1
			return start, index, plain, true
		case character == '\\':
			plain = false
			index++
		case character < 0x20:
			return 0, 0, false, false
		case character >= 0x80:
			plain = false
		}
	}
	return 0, 0, false, false
}

// skipValue goes past a value, for sing-box to read: it only finds its end. A comment
// stops it: sing-box's decoding takes comments out first.
func (r *reader) skipValue() bool {
	depth := 0
	for r.at < len(r.text) {
		switch r.text[r.at] {
		case '"':
			if _, _, _, ok := r.str(); !ok {
				return false
			}
			if depth == 0 {
				return true
			}
			continue
		case '[', '{':
			depth++
		case ']', '}':
			if depth == 0 {
				return true
			}
			depth--
			if depth == 0 {
				r.at++
				return true
			}
		case ',', ' ', '\t', '\n', '\r':
			if depth == 0 {
				return true
			}
		case '/', '#':
			return false
		}
		r.at++
	}
	return depth == 0
}

func (r *reader) space() {
	for r.at < len(r.text) {
		switch r.text[r.at] {
		case ' ', '\t', '\n', '\r':
			r.at++
		default:
			return
		}
	}
}

func (r *reader) take(character byte) bool {
	if r.at < len(r.text) && r.text[r.at] == character {
		r.at++
		return true
	}
	return false
}
