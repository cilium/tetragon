// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package explain

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
)

var (
	outputFormat string
	recursive    bool
	showExample  bool
	listMode     bool
	apiVersion   string
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain RESOURCE[.FIELD...]",
		Short: "List the fields for supported resources",
		Long: `Describe the fields of Tetragon Custom Resource Definitions (CRDs).
This command works similarly to 'kubectl explain' but does not require a Kubernetes cluster.

Supported resources are automatically discovered from available CRDs.

Path syntax supports both dot and bracket notation:
  tracingpolicy.spec.kprobes     (dot notation)
  tracingpolicy[spec][kprobes]   (bracket notation)
  tracingpolicy[spec].kprobes    (mixed notation)

Examples:
  tetra explain tracingpolicy
  tetra explain tracingpolicy.spec
  tetra explain tracingpolicy.spec.kprobes
  tetra explain tracingpolicy[spec][kprobes]
  tetra explain tp.spec.calls
  tetra explain podinfo
  tetra explain --list
  tetra explain tracingpolicy.spec --recursive
  tetra explain tracingpolicy.spec -o json
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if listMode {
				return nil // --list doesn't require args
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if listMode {
				listResources(cmd.OutOrStdout())
				return
			}

			if err := runExplain(cmd.OutOrStdout(), args[0]); err != nil {
				fmt.Fprintf(cmd.OutOrStderr(), "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. One of: json|yaml")
	cmd.Flags().BoolVarP(&recursive, "recursive", "R", false, "Print the fields of fields recursively")
	cmd.Flags().BoolVar(&showExample, "example", false, "Show example usage")
	cmd.Flags().BoolVar(&listMode, "list", false, "List all supported resources")
	cmd.Flags().StringVar(&apiVersion, "api-version", "", "Specify the API version to use")

	return cmd
}

func listResources(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSHORTNAMES")

	for _, crd := range client.AllCRDs {
		shortNames := strings.Join(crd.Definition.Spec.Names.ShortNames, ",")
		fmt.Fprintf(tw, "%s\t%s\n", crd.Definition.Spec.Names.Kind, shortNames)
	}
	tw.Flush()
}

// convertBracketsToDots converts bracket notation to dot notation using regex
func convertBracketsToDots(path string) string {
	path = strings.ReplaceAll(path, "][", ".")

	re := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\[([^\]]*)\]`)

	result := re.ReplaceAllStringFunc(path, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}

		fieldName := parts[1]
		bracketContent := strings.TrimSpace(parts[2])

		if bracketContent == "" || isNumeric(bracketContent) {
			return fieldName
		}

		return fieldName + "." + bracketContent
	})

	return result
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Normalize path by cleaning up empty segments and invalid characters
func normalizePath(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}

	// First convert bracket notation to dot notation
	convertedPath := convertBracketsToDots(path)

	parts := strings.Split(convertedPath, ".")
	var normalized []string

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if i == 0 || i == len(parts)-1 {
				return nil, errors.New("invalid path: cannot start or end with '.'")
			}
			continue // skip empty segments in middle
		}

		normalized = append(normalized, part)
	}

	if len(normalized) == 0 {
		return nil, errors.New("invalid path: no valid segments found")
	}

	return normalized, nil
}

func runExplain(w io.Writer, path string) error {
	parts, err := normalizePath(path)
	if err != nil {
		return err
	}

	resourceName := strings.ToLower(parts[0])

	// Find the crd by name or alias
	var crd *apiextensionsv1.CustomResourceDefinition

	for _, c := range client.AllCRDs {
		if strings.EqualFold(c.Definition.Spec.Names.Kind, resourceName) {
			crd = &c.Definition
			break
		}
		// Check aliases
		if slices.Contains(c.Definition.Spec.Names.ShortNames, resourceName) {
			crd = &c.Definition
			break
		}
	}

	if crd == nil {
		var supported []string
		for _, c := range client.AllCRDs {
			supported = append(supported, c.Definition.Spec.Names.Kind)
			supported = append(supported, c.Definition.Spec.Names.ShortNames...)
		}
		sort.Strings(supported)
		return fmt.Errorf("unsupported resource: %s (supported resources: %s)", resourceName, strings.Join(supported, ", "))
	}

	if len(crd.Spec.Versions) == 0 {
		return errors.New("no versions found in CRD")
	}

	// Select version
	var version *apiextensionsv1.CustomResourceDefinitionVersion

	if apiVersion != "" {
		for _, v := range crd.Spec.Versions {
			if v.Name == apiVersion {
				version = &v
				break
			}
		}
		if version == nil {
			return fmt.Errorf("version %s not found", apiVersion)
		}
	} else {
		// Use the latest version (usually the last one)
		version = &crd.Spec.Versions[len(crd.Spec.Versions)-1]
	}

	if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
		return errors.New("no schema found for CRD version")
	}

	current := version.Schema.OpenAPIV3Schema

	// Traverse the path using string builder for efficiency
	var fieldPathBuilder strings.Builder
	fieldPathBuilder.WriteString(crd.Spec.Names.Kind)

	for i, part := range parts[1:] {
		fieldPathBuilder.WriteString(".")
		fieldPathBuilder.WriteString(part)

		// If current is array, we implicitly look into its items properties for the next part
		if current.Type == "array" && current.Items != nil {
			current = current.Items.Schema
		}

		if len(current.Properties) == 0 {
			// Check if it has AdditionalProperties (Map)
			if current.AdditionalProperties != nil {
				current = current.AdditionalProperties.Schema
				continue
			}
			return fmt.Errorf("field %q does not have properties", fieldPathBuilder.String())
		}

		prop, ok := current.Properties[part]
		if !ok {
			availableFields := make([]string, 0, len(current.Properties))
			for k := range current.Properties {
				availableFields = append(availableFields, k)
			}
			sort.Strings(availableFields)
			return fmt.Errorf("field %q not found in %q (available fields: %s)",
				part, strings.Join(parts[:i+2], "."), strings.Join(availableFields, ", "))
		}
		current = &prop
	}

	// Handle different output formats
	switch outputFormat {
	case "json":
		return outputJSON(w, current)
	case "yaml":
		return outputYAML(w, current)
	default:
		return outputDefault(w, crd.Spec.Names.Kind, version.Name, parts, current)
	}
}

func outputJSON(w io.Writer, s *apiextensionsv1.JSONSchemaProps) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(data))
	return nil
}

func outputYAML(w io.Writer, s *apiextensionsv1.JSONSchemaProps) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	fmt.Fprint(w, string(data))
	return nil
}

func outputDefault(w io.Writer, kind, version string, parts []string, current *apiextensionsv1.JSONSchemaProps) error {
	// Print header
	fmt.Fprintf(w, "KIND:     %s\n", kind)
	fmt.Fprintf(w, "VERSION:  %s\n\n", version)

	if len(parts) == 1 {
		// Root resource
		fmt.Fprintf(w, "DESCRIPTION:\n%s\n\n", indent(current.Description, "     "))
	} else {
		// Specific field
		fmt.Fprintf(w, "FIELD:    %s <%s>\n\n", parts[len(parts)-1], getTypeString(current))
		if current.Description != "" {
			fmt.Fprintf(w, "DESCRIPTION:\n%s\n\n", indent(current.Description, "     "))
		}
	}

	// Show example if requested
	if showExample && current.Example != nil {
		fmt.Fprintf(w, "EXAMPLE:\n")
		exampleData, err := yaml.Marshal(current.Example)
		if err == nil {
			fmt.Fprintf(w, "%s\n", indent(string(exampleData), "     "))
		}
	}

	// Print fields
	if recursive {
		printFieldsRecursive(w, current, 0)
	} else {
		printFields(w, current)
	}

	return nil
}

func printFields(w io.Writer, s *apiextensionsv1.JSONSchemaProps) {
	// If array, print fields of items
	if s.Type == "array" && s.Items != nil {
		s = s.Items.Schema
	}

	if len(s.Properties) > 0 {
		fmt.Fprintf(w, "FIELDS:\n")
		keys := make([]string, 0, len(s.Properties))
		for k := range s.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		requiredSet := make(map[string]bool)
		for _, req := range s.Required {
			requiredSet[req] = true
		}

		for _, k := range keys {
			prop := s.Properties[k]
			required := ""
			if requiredSet[k] {
				required = " -required-"
			}
			fmt.Fprintf(w, "   %s\t<%s>%s\n", k, getTypeString(&prop), required)
			if prop.Description != "" {
				fmt.Fprintf(w, "%s\n", indent(prop.Description, "     "))
			}
			fmt.Fprintf(w, "\n")
		}
	} else if s.AdditionalProperties != nil {
		fmt.Fprintf(w, "FIELDS:\n")
		fmt.Fprintf(w, "   <map[string]%s>\n", getTypeString(s.AdditionalProperties.Schema))
		if s.AdditionalProperties.Schema.Description != "" {
			fmt.Fprintf(w, "%s\n", indent(s.AdditionalProperties.Schema.Description, "     "))
		}
		fmt.Fprintf(w, "\n")
	}
}

func printFieldsRecursive(w io.Writer, s *apiextensionsv1.JSONSchemaProps, depth int) {
	if depth > 5 { // Prevent infinite recursion
		return
	}

	// If array, print fields of items
	if s.Type == "array" && s.Items != nil {
		s = s.Items.Schema
	}

	if len(s.Properties) > 0 {
		if depth == 0 {
			fmt.Fprintf(w, "FIELDS:\n")
		}

		keys := make([]string, 0, len(s.Properties))
		for k := range s.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		requiredSet := make(map[string]bool)
		for _, req := range s.Required {
			requiredSet[req] = true
		}

		for _, k := range keys {
			prop := s.Properties[k]
			required := ""
			if requiredSet[k] {
				required = " -required-"
			}

			indentStr := strings.Repeat("  ", depth)
			fmt.Fprintf(w, "%s   %s\t<%s>%s\n", indentStr, k, getTypeString(&prop), required)

			if prop.Description != "" {
				baseIndent := indentStr + "     "
				fmt.Fprintf(w, "%s\n", indent(prop.Description, baseIndent))
			}

			// Recursive call for nested objects
			if prop.Type == "object" && len(prop.Properties) > 0 {
				printFieldsRecursive(w, &prop, depth+1)
			} else if prop.Type == "array" && prop.Items != nil && len(prop.Items.Schema.Properties) > 0 {
				printFieldsRecursive(w, prop.Items.Schema, depth+1)
			}

			fmt.Fprintf(w, "\n")
		}
	}
}

func getTypeString(s *apiextensionsv1.JSONSchemaProps) string {
	switch s.Type {
	case "array":
		if s.Items != nil {
			return "[]" + getTypeString(s.Items.Schema)
		}
		return "[]object"
	case "object":
		if s.AdditionalProperties != nil {
			return "map[string]" + getTypeString(s.AdditionalProperties.Schema)
		}
		return "object"
	case "":
		return "object"
	default:
		return s.Type
	}
}

func indent(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}
