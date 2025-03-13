package main

import (
	"fmt"

	xd "github.com/subchen/go-xmldom"
)

type SystemData struct {
	doc *xd.Document
}

func parseSystemData(s string) *SystemData {
	if len(s) == 0 {
		panic("Empty test data")
	}
	doc, err := xd.ParseXML("<system_data>" + s + "</system_data>")
	if err != nil {
		panic(fmt.Sprintf("Error parsing XML: %s", err.Error()))
	}
	return &SystemData{doc: doc}
}

func (s *SystemData) getItem(id string) map[string]string {
	r := s.doc.Root.FirstChild()
	for r != nil {
		if r.GetAttribute("id").Value == id {
			ret := make(map[string]string)
			for _, attr := range r.Attributes {
				ret["."+attr.Name] = attr.Value
			}
			for _, child := range r.Children {
				ret[child.Name] = child.Text
			}
			return ret
		}
		r = r.NextSibling()
	}
	return nil
}
