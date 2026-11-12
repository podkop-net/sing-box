package option

import "github.com/sagernet/sing-box/schema"

func (r V2RayXHTTPRange) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("V2RayXHTTPRange", func() (*schema.Node, error) {
		object := schema.StrictObject()
		object.Properties.Put("from", schema.IntegerNode())
		object.Properties.Put("to", schema.IntegerNode())
		return schema.AnyOf(&schema.Node{Type: "string", Pattern: `^(-?[0-9]+(--?[0-9]+)?)?$`}, schema.IntegerNode(), object), nil
	})
}
