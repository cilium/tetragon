// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel/model"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"
)

const (
	staticCRDCostLimit = uint64(100000000)
	defaultCRD         = "pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml"
	defaultOutput      = "results/tracingpolicy-cel-costs.md"
)

type ruleCost struct {
	path        string
	expression  string
	unitCost    uint64
	occurrences uint64
	cost        uint64
	fallback    bool
	message     bool
}

type costNode struct {
	path   string
	schema *schema.Structural
	own    uint64
	total  uint64
	fields map[string]*costNode
	items  *costNode
	values *costNode
}

type goField struct {
	name     string
	goType   string
	jsonName string
	shape    ast.Expr
}

type goStruct struct {
	name   string
	file   string
	line   int
	fields []goField
}

type structGroup struct {
	definition *goStruct
	node       *costNode
	code       string
	contexts   []string
}

func main() {
	crd := flag.String("crd", defaultCRD, "generated TracingPolicy CRD YAML (run from repository root)")
	output := flag.String("output", defaultOutput, "Markdown output path")
	version := flag.String("version", "", "CRD schema version; defaults to the first version")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments; use -help for usage")
		os.Exit(2)
	}
	if err := generate(*crd, *version, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(crdPath, version, output string) error {
	data, err := os.ReadFile(crdPath)
	if err != nil {
		return err
	}
	root, selectedVersion, err := loadSchema(data, version)
	if err != nil {
		return err
	}
	report, total, err := renderReport(root, data, crdPath, selectedVersion, output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(output, []byte(report), 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s: %s CEL cost units (%.9fx schema budget).\n", output, number(total), float64(total)/float64(staticCRDCostLimit))

	return nil
}

func loadSchema(data []byte, version string) (*schema.Structural, string, error) {
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict(data, &crd); err != nil {
		return nil, "", err
	}
	for index, candidate := range crd.Spec.Versions {
		if candidate.Name != version && !(version == "" && index == 0) {
			continue
		}
		if candidate.Schema == nil || candidate.Schema.OpenAPIV3Schema == nil {
			return nil, "", fmt.Errorf("CRD version %q has no OpenAPI schema", candidate.Name)
		}
		var internal apiextensions.JSONSchemaProps
		if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(candidate.Schema.OpenAPIV3Schema, &internal, nil); err != nil {
			return nil, "", err
		}
		root, err := schema.NewStructural(&internal)

		return root, candidate.Name, err
	}

	return nil, "", fmt.Errorf("CRD schema version %q not found", version)
}

func analyze(root *schema.Structural) (*costNode, []ruleCost, error) {
	cardinality := uint64(1)

	return analyzeNode(root, "root", &cardinality, true)
}

func analyzeNode(node *schema.Structural, path string, cardinality *uint64, isRoot bool) (*costNode, []ruleCost, error) {
	result := &costNode{path: path, schema: node, fields: make(map[string]*costNode)}
	var costs []ruleCost
	if len(node.XValidations) > 0 {
		compiled, err := schemacel.Compile(node, model.SchemaDeclType(node, isRoot), celconfig.PerCallLimit,
			environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()), schemacel.NewExpressionsEnvLoader())
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		for index, rule := range compiled {
			if rule.Error != nil {
				return nil, nil, fmt.Errorf("%s rule %d: %v", path, index, rule.Error)
			}
			if rule.MessageExpressionError != nil {
				return nil, nil, fmt.Errorf("%s messageExpression %d: %v", path, index, rule.MessageExpressionError)
			}
			occurrences := rule.MaxCardinality
			if cardinality != nil {
				occurrences = *cardinality
			}
			cost := multiply(rule.MaxCost, occurrences)
			costs = append(costs, ruleCost{path: path, expression: node.XValidations[index].Rule,
				unitCost: rule.MaxCost, occurrences: occurrences, cost: cost, fallback: cardinality == nil})
			result.own = add(result.own, cost)
			if rule.MessageExpression != nil {
				costs = append(costs, ruleCost{path: path, expression: node.XValidations[index].MessageExpression,
					unitCost: rule.MessageExpressionMaxCost, occurrences: 1, cost: rule.MessageExpressionMaxCost, message: true})
				result.own = add(result.own, rule.MessageExpressionMaxCost)
			}
		}
	}
	result.total = result.own
	childCardinality := cardinalityForChildren(node, cardinality)
	child := func(childSchema *schema.Structural, childPath string) (*costNode, error) {
		childNode, childCosts, err := analyzeNode(childSchema, childPath, childCardinality, childSchema.XEmbeddedResource)
		if err != nil {
			return nil, err
		}
		costs = append(costs, childCosts...)
		result.total = add(result.total, childNode.total)

		return childNode, nil
	}
	for name, property := range node.Properties {
		childNode, err := child(&property, path+"."+name)
		if err != nil {
			return nil, nil, err
		}
		result.fields[name] = childNode
	}
	if node.Items != nil {
		var err error
		result.items, err = child(node.Items, path+"[]")
		if err != nil {
			return nil, nil, err
		}
	}
	if node.AdditionalProperties != nil && node.AdditionalProperties.Structural != nil {
		var err error
		result.values, err = child(node.AdditionalProperties.Structural, path+"[*]")
		if err != nil {
			return nil, nil, err
		}
	}

	return result, costs, nil
}

func cardinalityForChildren(node *schema.Structural, cardinality *uint64) *uint64 {
	if cardinality == nil {
		return nil
	}
	var bound *int64
	switch node.Type {
	case "array":
		if node.ValueValidation != nil {
			bound = node.ValueValidation.MaxItems
		}
	case "object":
		if node.AdditionalProperties == nil {
			return cardinality
		}
		if node.ValueValidation != nil {
			bound = node.ValueValidation.MaxProperties
		}
	default:
		return cardinality
	}
	if bound == nil {
		return nil
	}
	result := multiply(*cardinality, uint64(max(0, *bound)))

	return &result
}

func multiply(first, second uint64) uint64 {
	if first != 0 && second > math.MaxUint64/first {
		return math.MaxUint64
	}

	return first * second
}

func add(first, second uint64) uint64 {
	if math.MaxUint64-first < second {
		return math.MaxUint64
	}

	return first + second
}

func number(value uint64) string {
	digits := strconv.FormatUint(value, 10)
	for offset := len(digits) - 3; offset > 0; offset -= 3 {
		digits = digits[:offset] + "," + digits[offset:]
	}

	return digits
}

func budgetSummary(total uint64) string {
	if total > staticCRDCostLimit {
		return "Over budget by " + number(total-staticCRDCostLimit) + " units."
	}

	return "Within budget; " + number(staticCRDCostLimit-total) + " units remaining."
}

func loadGoStructs() (map[string]*goStruct, error) {
	definitions := make(map[string]*goStruct)
	positions := token.NewFileSet()
	for _, pattern := range []string{"pkg/k8s/apis/cilium.io/v1alpha1/*.go", "pkg/k8s/slim/k8s/apis/meta/v1/*.go"} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(filepath.Base(path), "zz_") {
				continue
			}
			file, err := parser.ParseFile(positions, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, specification := range general.Specs {
					typeSpec, ok := specification.(*ast.TypeSpec)
					if !ok {
						continue
					}
					structure, ok := typeSpec.Type.(*ast.StructType)
					if !ok {
						continue
					}
					definition := &goStruct{name: typeSpec.Name.Name, file: path, line: positions.Position(typeSpec.Pos()).Line}
					for _, field := range structure.Fields.List {
						jsonName := ""
						if field.Tag != nil {
							tag, err := strconv.Unquote(field.Tag.Value)
							if err != nil {
								return nil, err
							}
							jsonName = strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
						}
						var goType bytes.Buffer
						if err := format.Node(&goType, positions, field.Type); err != nil {
							return nil, err
						}
						for _, name := range field.Names {
							fieldJSONName := jsonName
							if fieldJSONName == "" {
								fieldJSONName = name.Name
							}
							definition.fields = append(definition.fields, goField{name: name.Name, goType: goType.String(), jsonName: fieldJSONName, shape: field.Type})
						}
					}
					definitions[definition.name] = definition
				}
			}
		}
	}

	return definitions, nil
}

func renderStruct(definition *goStruct, node *costNode) (string, error) {
	var code strings.Builder
	fmt.Fprintf(&code, "package report\n\ntype %s struct {\n", definition.name)
	var fieldTotal uint64
	covered := make(map[string]bool)
	for _, field := range definition.fields {
		var cost uint64
		var detail string
		if child := node.fields[field.jsonName]; child != nil {
			cost = child.total
			detail = bounds(child.schema)
			if child.own > 0 {
				if detail != "" {
					detail += "; "
				}
				detail += "own=" + number(child.own)
			}
			covered[field.jsonName] = true
		} else if field.jsonName == "-" {
			detail = "excluded from CRD"
		}
		fieldTotal = add(fieldTotal, cost)
		fmt.Fprintf(&code, "\t%s %s // CEL subtree: %s", field.name, field.goType, number(cost))
		if detail != "" {
			fmt.Fprintf(&code, "; %s", detail)
		}
		code.WriteByte('\n')
	}
	code.WriteString("}\n")
	for name, child := range node.fields {
		if child.total > 0 && !covered[name] {
			return "", fmt.Errorf("unmapped cost-bearing field %s in %s", name, definition.name)
		}
	}
	if add(node.own, fieldTotal) != node.total {
		return "", fmt.Errorf("struct %s fields plus own cost do not match its subtree total", definition.name)
	}
	formatted, err := format.Source([]byte(code.String()))
	if err != nil {
		return "", err
	}

	return strings.TrimPrefix(string(formatted), "package report\n\n"), nil
}

func targetStruct(shape ast.Expr, node *costNode) (string, *costNode) {
	if node == nil {
		return "", nil
	}
	switch expression := shape.(type) {
	case *ast.StarExpr:
		return targetStruct(expression.X, node)
	case *ast.ArrayType:
		return targetStruct(expression.Elt, node.items)
	case *ast.MapType:
		return targetStruct(expression.Value, node.values)
	case *ast.Ident:
		return expression.Name, node
	case *ast.SelectorExpr:
		return expression.Sel.Name, node
	default:
		return "", nil
	}
}

func collectStructGroups(root *costNode, definitions map[string]*goStruct, costs []ruleCost) ([]*structGroup, error) {
	var groups []*structGroup
	byCode := make(map[string]*structGroup)
	visited := make(map[string]bool)
	var visit func(string, *costNode) error
	visit = func(name string, node *costNode) error {
		if node == nil || (node.total == 0 && name != "TracingPolicySpec") {
			return nil
		}
		definition := definitions[name]
		if definition == nil {
			return fmt.Errorf("missing Go struct for %s (%s); run from repository root", node.path, name)
		}
		code, err := renderStruct(definition, node)
		if err != nil {
			return err
		}
		key := name + "\n" + code + fmt.Sprint(node.own)
		for _, rule := range node.schema.XValidations {
			key += "\n" + rule.Rule + "\n" + rule.MessageExpression
		}
		group := byCode[key]
		if group == nil {
			group = &structGroup{definition: definition, node: node, code: code}
			byCode[key] = group
			groups = append(groups, group)
		}
		group.contexts = append(group.contexts, strings.TrimPrefix(node.path, "root."))
		visited[node.path] = true
		for _, field := range definition.fields {
			child := node.fields[field.jsonName]
			if child == nil || child.total == 0 {
				continue
			}
			visited[child.path] = true
			childName, target := targetStruct(field.shape, child)
			if err := visit(childName, target); err != nil {
				return err
			}
		}

		return nil
	}
	if root.fields["spec"] == nil {
		return nil, fmt.Errorf("CRD has no spec property")
	}
	if err := visit("TracingPolicySpec", root.fields["spec"]); err != nil {
		return nil, err
	}
	for _, rule := range costs {
		if !visited[rule.path] {
			return nil, fmt.Errorf("rule not represented by an annotated struct: %s", rule.path)
		}
	}

	return groups, nil
}

func renderReport(root *schema.Structural, source []byte, crdPath, version, output string) (string, uint64, error) {
	tree, costs, err := analyze(root)
	if err != nil {
		return "", 0, err
	}
	definitions, err := loadGoStructs()
	if err != nil {
		return "", 0, err
	}
	groups, err := collectStructGroups(tree, definitions, costs)
	if err != nil {
		return "", 0, err
	}
	spec := tree.fields["spec"]
	definition := definitions["TracingPolicySpec"]
	if tree.total != spec.total {
		return "", 0, fmt.Errorf("cost-bearing rules outside spec are not supported")
	}
	var report strings.Builder
	report.WriteString("<!-- Copyright (C) Isovalent, Inc. - All Rights Reserved. -->\n\n# TracingPolicy CEL Cost Map\n\n")
	fmt.Fprintf(&report, "Generated by `go run -mod=vendor ./tools/cel-cost/main.go` from the generated CRD, not directly from Go markers. Regenerate the CRD first after changing validation annotations. See [%s](%s).\n\n", "tools/cel-cost/README.md", relativeLink(output, "tools/cel-cost/README.md"))
	fmt.Fprintf(&report, "Schema version: `%s`. Source: [%s](%s). CRD SHA-256: `%x`. Kubernetes apiextensions-apiserver: `%s`.\n\n", version, crdPath, relativeLink(output, crdPath), sha256.Sum256(source), kubernetesVersion())
	fmt.Fprintf(&report, "**Total: %s CEL cost units / %s schema budget = %.9fx. %s**\n\n", number(tree.total), number(staticCRDCostLimit), float64(tree.total)/float64(staticCRDCostLimit), budgetSummary(tree.total))
	fmt.Fprintf(&report, "%d CEL rule/message expressions; %d top-level Go fields; %d distinct annotated struct/cost shapes.\n\n", len(costs), len(definition.fields), len(groups))
	report.WriteString("These are Kubernetes static worst-case CEL estimates, not measured execution times or Big-O complexity. `CEL subtree` includes rules attached to a field and every descendant. `own` is the part attached directly to that node. Parent and child costs overlap: do not add them together.\n\n")
	report.WriteString("Zero means no CEL rules are charged at or below that field; it does not mean the field has no OpenAPI validation. Zero-cost nested structs are collapsed, but every field of each displayed struct is annotated. A rule declared on a struct is charged to that struct's own cost, even when it reads one of the child fields.\n\n")
	report.WriteString("## Overview\n\n```mermaid\nflowchart LR\n")
	fmt.Fprintf(&report, "  root[\"TracingPolicySpec<br/>%s CEL<br/>%.9fx budget\"]\n", number(tree.total), float64(tree.total)/float64(staticCRDCostLimit))
	for index, field := range definition.fields {
		child := spec.fields[field.jsonName]
		if child == nil || child.total == 0 {
			continue
		}
		fmt.Fprintf(&report, "  field%d[\"%s<br/>%s CEL / %.2f%% of CRD<br/>%s\"]\n  root --> field%d\n", index, field.name, number(child.total), 100*float64(child.total)/float64(tree.total), bounds(child.schema), index)
	}
	if tree.total > staticCRDCostLimit {
		report.WriteString("  style root fill:#ffebee,stroke:#b71c1c,stroke-width:2px\n")
	} else {
		report.WriteString("  style root fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px\n")
	}
	report.WriteString("```\n\nZero-cost top-level fields are shown in the annotated TracingPolicySpec below.\n\n## Where Multipliers Explode\n\n")
	report.WriteString("An array without `maxItems`, or a map without `maxProperties`, leaves cardinality unbounded by the schema. Below an unbounded ancestor, Kubernetes uses a maximum occurrence count derived from the request-size limit and the rule scope's minimum serialized size. This is a conservative static bound, not an actual policy's entry count.\n\n")
	sort.Slice(costs, func(first, second int) bool {
		if costs[first].cost == costs[second].cost {
			if costs[first].path == costs[second].path {
				return costs[first].expression < costs[second].expression
			}
			return costs[first].path < costs[second].path
		}
		return costs[first].cost > costs[second].cost
	})
	shown := 0
	for _, rule := range costs {
		if rule.fallback && shown < 4 {
			fmt.Fprintf(&report, "- `%s`: **%s per evaluation x %s fallback occurrences = %s**.\n", strings.TrimPrefix(rule.path, "root."), number(rule.unitCost), number(rule.occurrences), number(rule.cost))
			shown++
		}
	}
	report.WriteString("\nAn unbounded collection with a zero-cost subtree is not itself a CEL hotspot. Explicit limits replace the fallback only when the entire ancestor collection chain is bounded.\n\n## Annotated Structs\n\n")
	report.WriteString("Identical Go types with identical costs are grouped. Listed contexts are separate contributions to the CRD total, not a shared charge.\n\n")
	for index, group := range groups {
		if index > 0 {
			fmt.Fprintf(&report, "<details>\n<summary>%s: %s CEL per context; %d context(s)</summary>\n\n", group.definition.name, number(group.node.total), len(group.contexts))
		}
		fmt.Fprintf(&report, "### %s\n\nSource: [%s](%s#L%d).\n\n", group.definition.name, group.definition.file, relativeLink(output, group.definition.file), group.definition.line)
		fmt.Fprintf(&report, "**Own CEL: %s. Inclusive CEL: %s per context.**\n\nContexts:\n", number(group.node.own), number(group.node.total))
		for _, context := range group.contexts {
			fmt.Fprintf(&report, "- `%s`\n", context)
		}
		fmt.Fprintf(&report, "\n```go\n%s```\n\n", group.code)
		if len(group.node.schema.XValidations) > 0 {
			report.WriteString("Rules attached to this struct:\n\n")
			for _, rule := range group.node.schema.XValidations {
				fmt.Fprintf(&report, "```cel\n%s\n```\n\n", rule.Rule)
			}
		}
		if index > 0 {
			report.WriteString("</details>\n\n")
		}
	}
	report.WriteString("## Full Positive-Cost Tree\n\n<details>\n<summary>Expand every cost-bearing schema path</summary>\n\n```text\n")
	writeCostTree(&report, spec, "", "spec")
	report.WriteString("```\n\n</details>\n\n## Per-Rule Amplification\n\n<details>\n<summary>All CEL expressions, raw costs, and cardinality multipliers</summary>\n\n")
	report.WriteString("| Schema path | Raw CEL cost | Occurrences | Cardinality basis | Weighted cost | Expression |\n|---|---:|---:|---|---:|---|\n")
	for _, rule := range costs {
		basis := "explicit ancestor bounds"
		if rule.fallback {
			basis = "request-size fallback"
		} else if rule.message {
			basis = "messageExpression (once)"
		}
		fmt.Fprintf(&report, "| `%s` | %s | %s | %s | %s | `%s` |\n", strings.TrimPrefix(rule.path, "root."), number(rule.unitCost), number(rule.occurrences), basis, number(rule.cost), strings.ReplaceAll(rule.expression, "|", "\\|"))
	}
	report.WriteString("\n</details>\n")

	return report.String(), tree.total, nil
}

func writeCostTree(output *strings.Builder, node *costNode, prefix, label string) {
	fmt.Fprintf(output, "%s%s: %s (own=%s)", prefix, label, number(node.total), number(node.own))
	if detail := bounds(node.schema); detail != "" {
		fmt.Fprintf(output, " [%s]", detail)
	}
	output.WriteByte('\n')
	var names []string
	for name, child := range node.fields {
		if child.total > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		writeCostTree(output, node.fields[name], prefix+"  ", name)
	}
	if node.items != nil && node.items.total > 0 {
		writeCostTree(output, node.items, prefix+"  ", "[] element")
	}
	if node.values != nil && node.values.total > 0 {
		writeCostTree(output, node.values, prefix+"  ", "[*] value")
	}
}

func bounds(node *schema.Structural) string {
	var values []string
	if node.Type == "array" {
		value := "unbounded"
		if node.ValueValidation != nil && node.ValueValidation.MaxItems != nil {
			value = fmt.Sprint(*node.ValueValidation.MaxItems)
		}
		values = append(values, "maxItems="+value)
	}
	if node.Type == "object" && node.AdditionalProperties != nil && node.AdditionalProperties.Structural != nil {
		value := "unbounded"
		if node.ValueValidation != nil && node.ValueValidation.MaxProperties != nil {
			value = fmt.Sprint(*node.ValueValidation.MaxProperties)
		}
		values = append(values, "maxProperties="+value)
	}
	if node.Type == "string" && node.ValueValidation != nil && node.ValueValidation.MaxLength != nil {
		values = append(values, fmt.Sprintf("maxLength=%d", *node.ValueValidation.MaxLength))
	}

	return strings.Join(values, ", ")
}

func relativeLink(output, target string) string {
	base, baseErr := filepath.Abs(filepath.Dir(output))
	path, pathErr := filepath.Abs(target)
	if baseErr == nil && pathErr == nil {
		if relative, err := filepath.Rel(base, path); err == nil {
			return strings.ReplaceAll(filepath.ToSlash(relative), " ", "%20")
		}
	}

	return filepath.ToSlash(target)
}

func kubernetesVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range info.Deps {
			if dependency.Path == "k8s.io/apiextensions-apiserver" {
				return dependency.Version
			}
		}
	}

	return "unknown"
}
