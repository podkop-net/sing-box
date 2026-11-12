package sharelink

import (
	"bytes"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// object is a JSON object that keeps the order of its keys: the options of an outbound as
// the configuration writes them, by name. The decoder fills it by option names and not
// through the option structures, so that its text is the same for every sing-box it is
// built into, whatever options that one has; what an option is worth there is for the
// configuration reader and the outbound itself to say.
//
// A value is another object, a list ([]any), or anything else JSON has a form for.
type object struct {
	keys   []string
	values map[string]any
}

func newObject() *object {
	return &object{values: make(map[string]any)}
}

func (o *object) get(key string) (any, bool) {
	value, exists := o.values[key]
	return value, exists
}

func (o *object) put(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *object) remove(key string) {
	if _, exists := o.values[key]; !exists {
		return
	}
	delete(o.values, key)
	for index, name := range o.keys {
		if name == key {
			o.keys = append(o.keys[:index], o.keys[index+1:]...)
			break
		}
	}
}

func (o *object) empty() bool {
	return len(o.keys) == 0
}

// child returns the object under key, making it when there is none. A value that is not
// an object is replaced.
func (o *object) child(key string) *object {
	if existing, isObject := o.values[key].(*object); isObject {
		return existing
	}
	created := newObject()
	o.put(key, created)
	return created
}

// set puts value at a path of names separated by dots.
func (o *object) set(path string, value any) {
	current := o
	for {
		name, rest, nested := strings.Cut(path, ".")
		if !nested {
			current.put(name, value)
			return
		}
		current = current.child(name)
		path = rest
	}
}

// at returns the value at a path of names separated by dots.
func (o *object) at(path string) (any, bool) {
	current := o
	for {
		name, rest, nested := strings.Cut(path, ".")
		value, exists := current.values[name]
		if !exists || !nested {
			return value, exists
		}
		next, isObject := value.(*object)
		if !isObject {
			return nil, false
		}
		current = next
		path = rest
	}
}

// text returns the string at a path, empty when there is none.
func (o *object) text(path string) string {
	value, _ := o.at(path)
	text, _ := value.(string)
	return text
}

func (o *object) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, key := range o.keys {
		if index > 0 {
			buffer.WriteByte(',')
		}
		name, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buffer.Write(name)
		buffer.WriteByte(':')
		value, err := json.Marshal(o.values[key])
		if err != nil {
			return nil, err
		}
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// parseObject reads a JSON object, keeping the order of its keys and the text of its
// numbers.
func parseObject(content []byte) (*object, error) {
	value, err := parseValue(content)
	if err != nil {
		return nil, err
	}
	parsed, isObject := value.(*object)
	if !isObject {
		return nil, E.New("not a JSON object")
	}
	return parsed, nil
}

func parseValue(content []byte) (any, error) {
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return nil, E.New("empty JSON value")
	}
	switch content[0] {
	case '{':
		decoder := json.NewDecoder(bytes.NewReader(content))
		_, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		result := newObject()
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, isString := keyToken.(string)
			if !isString {
				return nil, E.New("invalid JSON object")
			}
			var raw json.RawMessage
			err = decoder.Decode(&raw)
			if err != nil {
				return nil, err
			}
			value, err := parseValue(raw)
			if err != nil {
				return nil, err
			}
			result.put(key, value)
		}
		_, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		if decoder.More() {
			return nil, E.New("text after the JSON object")
		}
		return result, nil
	case '[':
		var items []json.RawMessage
		err := json.Unmarshal(content, &items)
		if err != nil {
			return nil, err
		}
		list := make([]any, 0, len(items))
		for _, item := range items {
			value, err := parseValue(item)
			if err != nil {
				return nil, err
			}
			list = append(list, value)
		}
		return list, nil
	case '"':
		var text string
		err := json.Unmarshal(content, &text)
		if err != nil {
			return nil, err
		}
		return text, nil
	case 't', 'f':
		var flag bool
		err := json.Unmarshal(content, &flag)
		if err != nil {
			return nil, err
		}
		return flag, nil
	case 'n':
		var null any
		err := json.Unmarshal(content, &null)
		if err != nil {
			return nil, err
		}
		return nil, nil
	default:
		// a number, kept as it is written
		var number json.RawMessage
		err := json.Unmarshal(content, &number)
		if err != nil {
			return nil, err
		}
		return number, nil
	}
}

// objectOf turns the options of an outbound into an object, through the JSON they are
// written as.
func objectOf(options any) (*object, error) {
	content, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	return parseObject(content)
}
