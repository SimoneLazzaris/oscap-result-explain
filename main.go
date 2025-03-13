package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
)

type RawXML struct {
	InnerXML string `xml:",innerxml"`
}

type ovalResult struct {
	XMLName     xml.Name           `xml:"oval_results"`
	Definitions Definitions        `xml:"oval_definitions"`
	Vars        RawXML             `xml:"variables"`
	ResultDefs  []ResultDefinition `xml:"results>system>definitions>definition"`
	TestResults []TestResult       `xml:"results>system>tests>test"`
	SystemData  RawXML             `xml:"results>system>oval_system_characteristics>system_data"`
}

type Definitions struct {
	Definitions      []Definition `xml:"definitions>definition"`
	RPMInfoTests     []TestDef    `xml:"tests>rpminfo_test"`
	FileContentTests []TestDef    `xml:"tests>textfilecontent54_test"`
	Objects          RawXML       `xml:"objects"`
	States           RawXML       `xml:"states"`
}

type Definition struct {
	ID       string   `xml:"id,attr"`
	Version  string   `xml:"version,attr"`
	Class    string   `xml:"class,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}

type Metadata struct {
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	Reference   []Reference `xml:"reference"`
	Advisory    Advisory    `xml:"advisory"`
}

type Reference struct {
	ID     string `xml:"ref_id,attr"`
	URL    string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

type Advisory struct {
	From            string   `xml:"from,attr"`
	Severity        string   `xml:"severity"`
	Rights          string   `xml:"rights"`
	Issued          RawXML   `xml:"issued"`
	Updated         RawXML   `xml:"updated"`
	CVE             []CVE    `xml:"cve"`
	AffectedCPEList []string `xml:"affected_cpe_list>cpe"`
}

type CVE struct {
	CVE    string `xml:",chardata"`
	CVSS3  string `xml:"cvss3,attr"`
	CWE    string `xml:"cwe,attr"`
	HRef   string `xml:"href,attr"`
	Impact string `xml:"impact,attr"`
	Public string `xml:"public,attr"`
}

type Criteria struct {
	Operator         string           `xml:"operator,attr"`
	Comment          string           `xml:"comment,attr"`
	Criterion        []Criterion      `xml:"criterion"`
	Criteria         []Criteria       `xml:"criteria"`
	ExtendDefinition ExtendDefinition `xml:"extend_definition"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
	Negate  string `xml:"negate,attr"`
}

type ExtendDefinition struct {
	DefinitionRef string `xml:"definition_ref,attr"`
}

type ResultDefinition struct {
	ID       string         `xml:"definition_id,attr"`
	Result   string         `xml:"result,attr"`
	Criteria CriteriaResult `xml:"criteria"`
}

type CriteriaResult struct {
	Operator         string            `xml:"operator,attr"`
	Comment          string            `xml:"comment,attr"`
	Result           string            `xml:"result,attr"`
	Criterion        []CriterionResult `xml:"criterion"`
	Criteria         []CriteriaResult  `xml:"criteria"`
	ExtendDefinition ExtendDefinition  `xml:"extend_definition"`
}

type CriterionResult struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
	Negate  string `xml:"negate,attr"`
	Result  string `xml:"result,attr"`
}

type TestDef struct {
	ID      string       `xml:"id,attr"`
	Comment string       `xml:"comment,attr"`
	Objects []TestObject `xml:"object"`
	States  []TestState  `xml:"state"`
}

type TestObject struct {
	Ref string `xml:"object_ref,attr"`
}
type TestState struct {
	Ref string `xml:"state_ref,attr"`
}
type TestResult struct {
	ID     string     `xml:"test_id,attr"`
	Result string     `xml:"result,attr"`
	Items  []TestItem `xml:"tested_item"`
}

type TestItem struct {
	Result string `xml:"result,attr"`
	ID     string `xml:"item_id,attr"`
}

type TestWComment struct {
	id      string
	comment string
}

func (or *ovalResult) scanCriteria(criteria Criteria, level int) []TestWComment {
	// prefix := strings.Repeat(" ", level*2)
	var result []TestWComment
	for _, ca := range criteria.Criteria {
		result = append(result, or.scanCriteria(ca, level+1)...)
	}
	for _, co := range criteria.Criterion {
		// fmt.Printf("%s- %s: %s\n", prefix, co.TestRef, co.Comment)
		result = append(result, TestWComment{co.TestRef, co.Comment})
	}
	return result
}

func (or *ovalResult) getDefinitionResult(defRef string) string {
	for _, result := range or.ResultDefs {
		if result.ID == defRef {
			return result.Result
		}
	}
	return "???"
}

func (or *ovalResult) getTestResultTail(cr CriteriaResult, testRef string) string {
	for _, co := range cr.Criterion {
		if co.TestRef == testRef {
			return co.Result
		}
	}
	for _, ca := range cr.Criteria {
		ret := or.getTestResultTail(ca, testRef)
		if ret != "" {
			return ret
		}
	}
	return ""
}

func (or *ovalResult) getTestResult(testRef string) string {
	for _, result := range or.ResultDefs {
		if ret := or.getTestResultTail(result.Criteria, testRef); ret != "" {
			return ret
		}
	}
	return "???"
}

func (or *ovalResult) sortTests() {
	slices.SortFunc(or.TestResults, func(a, b TestResult) int {
		return strings.Compare(a.ID, b.ID)
	})
}

func (or *ovalResult) getTestItem(testId string) *TestResult {
	res, ok := slices.BinarySearchFunc(or.TestResults, testId, func(a TestResult, b string) int {
		return strings.Compare(a.ID, b)
	})
	if ok {
		return &or.TestResults[res]
	}
	return nil
}

//---

func main() {
	filename := flag.String("filename", "result.xml", "oscap result file")
	cveid := flag.String("cveid", "", "CVE ID to filter by")
	flag.Parse()

	file, err := os.Open(*filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	var result ovalResult
	err = xml.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshalling XML:", err)
		return
	}
	result.sortTests()
	fmt.Printf("RPMInfoTests: %d\n", len(result.Definitions.RPMInfoTests))
	fmt.Printf("FileContentTests: %d\n", len(result.Definitions.FileContentTests))
	sysData := parseSystemData(result.SystemData.InnerXML)
	for _, d := range result.Definitions.Definitions {
		id := d.ID
		for _, r := range d.Metadata.Reference {
			if *cveid != "" && r.ID != *cveid {
				continue
			}
			fmt.Printf("%s: %s <%s>\n", id, r.ID, result.getDefinitionResult(id))
			fmt.Println("Criteria:")
			testRefs := result.scanCriteria(d.Criteria, 1)
			slices.SortFunc(testRefs, func(a, b TestWComment) int {
				return strings.Compare(a.id, b.id)
			})
			for _, testRef := range testRefs {
				fmt.Printf("%s: %s\n", testRef.id, result.getTestResult(testRef.id))
				if test := result.getTestItem(testRef.id); test != nil {
					fmt.Printf("  %s: %s <%s>\n", test.ID, testRef.comment, test.Result)
					for _, item := range test.Items {
						fmt.Printf("  item %s: %s\n", item.ID, item.Result)
						sd := sysData.getItem(item.ID)
						for _, k := range slices.Sorted(maps.Keys(sd)) {
							fmt.Printf("      %s: %s\n", k, sd[k])
						}
					}
				} else {
					fmt.Printf("  %s: %s <%s>\n", testRef.id, testRef.comment, "not found")
				}
			}
		}
	}
}
