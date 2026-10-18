package domainset

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/varbin"

	"github.com/stretchr/testify/require"
)

// sourceText makes the text of rule sets of the source format of every shape sing-box
// reads, and of shapes it does not: white space of all kinds, a string or an array or
// null or an empty array, escapes, names not of ASCII and bytes not of UTF-8, the other
// fields of a rule, logical rules, keys in other letters or twice, unknown keys,
// comments, trailing commas, versions it does not know.
type sourceText struct {
	random *rand.Rand
	// names: how many names a list has at most
	names int
}

func (g sourceText) one(choices ...string) string {
	return choices[g.random.Intn(len(choices))]
}

func (g sourceText) space() string {
	if g.random.Intn(3) > 0 {
		return g.one("", " ")
	}
	return g.one("\n", "\t", "\r\n  ", "  ")
}

func (g sourceText) name() string {
	switch g.random.Intn(30) {
	case 0:
		return ""
	case 1:
		return "Пример.РФ"
	case 2:
		return "Example.COM"
	case 3:
		return ".example.com"
	case 4:
		return "a\nb"
	}
	letters := "abcdefghijklmnopqrstuvwxyz0123456789-"
	var name strings.Builder
	if g.random.Intn(8) == 0 {
		name.WriteByte('.')
	}
	for range 1 + g.random.Intn(2) {
		for range 1 + g.random.Intn(6) {
			name.WriteByte(letters[g.random.Intn(len(letters))])
		}
		name.WriteByte('.')
	}
	name.WriteString(g.one("com", "net", "ru", "io", "co.uk", "рф"))
	return name.String()
}

// quote writes a string as JSON, now and then with escapes or bytes JSON does not have.
func (g sourceText) quote(value string) string {
	switch g.random.Intn(40) {
	case 0:
		return `"` + strings.ReplaceAll(value, "a", `a`) + `"`
	case 1:
		return `"` + strings.ReplaceAll(value, ".", `\/.`) + `"`
	case 2:
		return "\"" + value + "\xff\""
	case 3:
		return "\"" + value + "\x01\""
	}
	quoted, _ := json.Marshal(value)
	return string(quoted)
}

func (g sourceText) list(name func() string) string {
	switch g.random.Intn(12) {
	case 0:
		return "null"
	case 1:
		return "[]"
	case 2:
		return g.quote(name())
	case 3:
		return "[" + g.quote(name()) + ", null]"
	case 4:
		return "[[]]"
	case 5:
		return "42"
	}
	count := 1 + g.random.Intn(g.names)
	items := make([]string, count)
	for index := range items {
		items[index] = g.quote(name())
	}
	separator := ","
	if g.random.Intn(2) == 0 {
		separator = "," + g.space()
	}
	return "[" + g.space() + strings.Join(items, separator) + g.space() + "]"
}

func (g sourceText) member(key string, value string) string {
	return g.quote(key) + g.space() + ":" + g.space() + value
}

func (g sourceText) rule(depth int) string {
	var members []string
	add := func(key string, value string) {
		members = append(members, g.member(key, value))
	}
	cidr := func() string { return g.one("10.0.0.0/8", "192.0.2.1", "2001:db8::/32", "bad") }
	word := func() string { return g.one("ex", "ample", "^a.*$", "q") }
	for range 1 + g.random.Intn(4) {
		switch g.random.Intn(22) {
		case 0, 1, 2:
			add("domain_suffix", g.list(g.name))
		case 3, 4:
			add("domain", g.list(g.name))
		case 5:
			add("domain_keyword", g.list(word))
		case 6:
			add("domain_regex", g.list(word))
		case 7:
			add("ip_cidr", g.list(cidr))
		case 8:
			add("source_ip_cidr", g.list(cidr))
		case 9:
			add("port", g.one("80", "[80, 443]", "[]", `"x"`))
		case 10:
			add("network", g.one(`"tcp"`, `["udp"]`, `"bad"`))
		case 11:
			add("invert", g.one("true", "false"))
		case 12:
			add("query_type", g.one(`["A", "AAAA"]`, `"HTTPS"`))
		case 13:
			add("type", g.one(`"default"`, `""`, `"bad"`, `"logical"`))
		case 14:
			add(g.one("Domain_Suffix", "DOMAIN", "Type", "domain_ſuffix"), g.list(g.name))
		case 15:
			add(g.one("foo", "domain suffix"), `"x"`)
		case 16:
			add("network_interface_address", g.one("{}", `{"wifi": []}`, `{"wifi": ["10.0.0.0/8"]}`))
		case 17:
			add("port_range", g.one(`["1000:2000"]`, "[]", "null"))
		case 18:
			if depth < 2 {
				return "{" + g.space() + strings.Join([]string{
					g.member("type", `"logical"`), g.member("mode", g.one(`"and"`, `"or"`)),
					g.member("rules", "["+g.rule(depth+1)+","+g.space()+g.rule(depth+1)+"]"),
				}, ",") + "}"
			}
		case 19:
			if len(members) > 0 {
				// a key twice
				members = append(members, members[0])
			}
		case 20:
			add("domain_suffix", g.list(g.name))
			members = append(members, g.one("/* a */ ", "// a\n", "# a\n")+members[len(members)-1])
		case 21:
			add("domain_suffix", `"domain.ru"`)
		}
	}
	g.random.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
	text := "{" + g.space() + strings.Join(members, ","+g.space()) + g.space()
	if g.random.Intn(30) == 0 {
		text += ","
	}
	return text + "}"
}

func (g sourceText) set() string {
	var members []string
	switch g.random.Intn(20) {
	case 0:
	case 1:
		members = append(members, g.member("version", g.one("0", "9", "3.0", `"3"`, "1e0", "-1", "33")))
	case 2:
		members = append(members, g.member("Version", "3"))
	default:
		members = append(members, g.member("version", fmt.Sprint(1+g.random.Intn(C.RuleSetVersionCurrent))))
	}
	switch g.random.Intn(15) {
	case 0:
	case 1:
		members = append(members, g.member("rules", g.one("[]", "null", "{}", "[{}]", `[{"domain": []}, {}]`)))
	default:
		count := g.random.Intn(4)
		rules := make([]string, count)
		for index := range rules {
			rules[index] = g.rule(0)
		}
		members = append(members, g.member("rules", "["+g.space()+strings.Join(rules, ","+g.space())+g.space()+"]"))
	}
	if g.random.Intn(30) == 0 {
		members = append(members, g.member("extra", "1"))
	}
	g.random.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
	text := g.space() + "{" + g.space() + strings.Join(members, ","+g.space()) + g.space() + "}" + g.space()
	if g.random.Intn(40) == 0 {
		text = "// a rule set\n" + text
	}
	return text
}

// written is a trie as a rule set carries it.
func written(t testing.TB, matcher interface{ Write(varbin.Writer) error }) []byte {
	var content bytes.Buffer
	require.NoError(t, matcher.Write(&content))
	return content.Bytes()
}

// sameAsStock checks one text: what readSource reads of it is what sing-box reads, its
// matchers the ones route/rule builds; text sing-box refuses is not read here. It tells
// whether readSource read the text.
func sameAsStock(t testing.TB, text []byte) bool {
	stock, stockErr := json.UnmarshalExtended[option.PlainRuleSetCompat](text)
	fast, ok := readSource(text)
	if stockErr != nil {
		require.False(t, ok, "sing-box refuses it (%v), readSource read it:\n%s", stockErr, text)
		return false
	}
	if !ok {
		return false
	}
	require.Equal(t, len(stock.Options.Rules), len(fast.Options.Rules), "%s", text)
	for index := range stock.Options.Rules {
		mine, theirs := &fast.Options.Rules[index].DefaultOptions, &stock.Options.Rules[index].DefaultOptions
		if slices.Contains(theirs.Domain, "") || slices.Contains(theirs.DomainSuffix, "") {
			// route/rule refuses an empty name: the rule must reach it as lists
			require.Nil(t, mine.DomainSet, "an empty name built here:\n%s", text)
		}
		if mine.DomainSet == nil {
			continue
		}
		require.True(t, len(theirs.Domain)+len(theirs.DomainSuffix) > 0, "%s", text)
		var want *domain.Matcher
		func() {
			defer func() {
				if recover() != nil {
					want = nil
				}
			}()
			want = domain.NewMatcher(theirs.Domain, theirs.DomainSuffix, false)
		}()
		require.NotNil(t, want, "sing stops on these names, readSource built them:\n%s", text)
		require.Equal(t, written(t, want), written(t, mine.DomainSet), "%s", text)
		require.Equal(t, Describe(theirs.Domain[:min(3, len(theirs.Domain))], len(theirs.Domain),
			theirs.DomainSuffix[:min(3, len(theirs.DomainSuffix))], len(theirs.DomainSuffix)), mine.DomainSet.String(), "%s", text)
		mine.DomainSet = nil
		theirs.Domain, theirs.DomainSuffix = nil, nil
	}
	require.True(t, reflect.DeepEqual(stock, fast), "%s\nsing-box: %#v\nhere: %#v", text, stock, fast)
	return true
}

// What the source format reads here is what sing-box reads, for a hundred thousand rule
// sets of every shape; and ReadSource gives what sing-box gives for each of them, an error
// included.
func TestReadSourceSameAsStock(t *testing.T) {
	random := rand.New(rand.NewSource(4))
	read := 0
	const sets = 100000
	for index := range sets {
		g := sourceText{random: random, names: 4}
		if index%100 == 0 {
			g.names = 200
		}
		text := []byte(g.set())
		if sameAsStock(t, text) {
			read++
		}
		if index%10 == 0 {
			stock, stockErr := json.UnmarshalExtended[option.PlainRuleSetCompat](text)
			mine, err := ReadSource(text)
			if stockErr != nil {
				require.EqualError(t, err, stockErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, len(stock.Options.Rules), len(mine.Options.Rules))
			}
		}
	}
	t.Logf("read here: %d of %d", read, sets)
	// the shapes a list of podkop and of the lists published as rule sets have are read
	// here, not left to sing-box
	require.Greater(t, read, sets/4)
}

// Rule sets as they are written in the wild are read here.
func TestReadSourceShapes(t *testing.T) {
	for _, text := range []string{
		`{"version": 3, "rules": [{"domain_suffix": ["example.com", "example.org"]}]}`,
		"{\n  \"version\": 2,\n  \"rules\": [\n    {\n      \"domain_suffix\": [\n        \"a.ru\",\n        \"b.ru\"\n      ]\n    }\n  ]\n}\n",
		`{"version":1,"rules":[{"domain":["a.com"],"domain_suffix":[".b.com"],"domain_keyword":["k"],"domain_regex":["^r$"]},{"ip_cidr":["10.0.0.0/8"]}]}`,
		`{"version": 3, "rules": [{"domain_suffix": "one.example", "port": [80, 443], "invert": true}]}`,
		`{"rules": [{"type": "default", "domain": "x.example"}], "version": 3}`,
		`{"version": 3}`,
		`{"version": 3, "rules": []}`,
		`{"version": 3, "rules": [{"domain": "x"}, {"type": "logical", "mode": "and", "rules": [{"domain": "y"}, {"port": 80}]}]}`,
	} {
		require.True(t, sameAsStock(t, []byte(text)), "not read here:\n%s", text)
	}
	for _, text := range []string{
		// comments, a version that is not a digit, a key in other letters: sing-box's
		`// a set` + "\n" + `{"version": 3, "rules": []}`,
		`{"version": "3", "rules": []}`,
		`{"version": 3, "Rules": []}`,
		`{"version": 3, "rules": [{"domain": "x"},]}`,
	} {
		require.False(t, sameAsStock(t, []byte(text)), "read here:\n%s", text)
	}
}

func FuzzReadSource(f *testing.F) {
	random := rand.New(rand.NewSource(5))
	for range 200 {
		f.Add([]byte(sourceText{random: random, names: 3}.set()))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		sameAsStock(t, text)
	})
}

// sourceList is a rule set of count varied names as one list of domain_suffix, the way
// podkop writes its lists.
func sourceList(count int) []byte {
	list := names(rand.New(rand.NewSource(6)), count)
	var text bytes.Buffer
	text.WriteString(`{"version": 3, "rules": [{"domain_suffix": [`)
	for index, name := range list {
		if index > 0 {
			text.WriteByte(',')
		}
		quoted, _ := json.Marshal(name)
		text.Write(quoted)
	}
	text.WriteString("]}]}")
	return text.Bytes()
}

// What reading a rule set of 100000 names and building its matcher costs: sing-box with
// the matcher of sing, sing-box with the builder of this package, and ReadSource.
func BenchmarkReadSource(b *testing.B) {
	for _, count := range []int{100000, 300000} {
		text := sourceList(count)
		b.Run(fmt.Sprint(count, "/sing"), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](text)
				if err != nil {
					b.Fatal(err)
				}
				rule := compat.Options.Rules[0].DefaultOptions
				domain.NewMatcher(rule.Domain, rule.DomainSuffix, false)
			}
		})
		b.Run(fmt.Sprint(count, "/stock-json"), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](text)
				if err != nil {
					b.Fatal(err)
				}
				rule := compat.Options.Rules[0].DefaultOptions
				_, err = NewSet(rule.Domain, rule.DomainSuffix)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprint(count, "/ReadSource"), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				compat, err := ReadSource(text)
				if err != nil || compat.Options.Rules[0].DefaultOptions.DomainSet == nil {
					b.Fatal(err)
				}
			}
		})
	}
}
