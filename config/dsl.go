package config

import (
	"fmt"
	"net/url"
	"strings"
)

func ProcessDSL(input string) (string, error) {
	var result strings.Builder
	lines := strings.Split(input, "\n")
	inMultiComment := false
	inMultiString := false

	for _, line := range lines {
		inString := false
		inComment := false
		stringQuote := byte(0)
		needReplace := false

		for i := 0; i < len(line); i++ {
			switch {
			// Multiline comment start
			case !inString && !inMultiString && i < len(line)-1 && line[i:i+2] == "--" && i < len(line)-3 && line[i+2:i+4] == "[[":
				inMultiComment = true
				inComment = true
				i += 3
			// Multiline comment end
			case inMultiComment && i < len(line)-1 && line[i:i+2] == "]]":
				inMultiComment = false
				i++
			// Singleline comment
			case !inString && !inMultiString && i < len(line)-1 && line[i:i+2] == "--":
				inComment = true
				i++
			// Multiline string start
			case !inString && !inComment && i < len(line)-1 && line[i:i+2] == "[[":
				inMultiString = true
				i++
			// Multiline string end
			case inMultiString && i < len(line)-1 && line[i:i+2] == "]]":
				inMultiString = false
				i++
			// Common string
			case !inMultiString && !inComment && (line[i] == '"' || line[i] == '\''):
				if !inString {
					inString = true
					stringQuote = line[i]
				} else if stringQuote == line[i] && (i == 0 || line[i-1] != '\\') {
					inString = false
				}
			// Standalone ->
			case !inString && !inComment && !inMultiString && !inMultiComment && i < len(line)-1 && line[i:i+2] == "->":
				needReplace = true
			}
		}

		if needReplace {
			str, err := processArrowLine(line)
			if err != nil {
				return "", fmt.Errorf("error: %s", err)
			}
			result.WriteString(str)
		} else {
			result.WriteString(line)
		}
		result.WriteByte('\n')
	}
	return strings.TrimRight(result.String(), "\n"), nil
}

func processArrowLine(line string) (string, error) {
	line = strings.TrimSpace(line)

	// Split by '|' and trim spaces from each part
	parts := strings.Split(line, "|")
	var arrowMappingPart string
	var optionsParts []string

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return "", fmt.Errorf("useless | found in line: %s", line)
		}
		if strings.Contains(trimmed, "->") {
			// Ensure that only one mapping part exists
			if arrowMappingPart != "" {
				return "", fmt.Errorf("multiple arrow mappings found in line: %s", line)
			}
			arrowMappingPart = trimmed
		} else {
			optionsParts = append(optionsParts, trimmed)
		}
	}

	if arrowMappingPart == "" {
		return "", fmt.Errorf("no arrow mapping found in line: %s", line)
	}

	// Parse the arrow mapping part into domain and target
	arrowParts := strings.SplitN(arrowMappingPart, "->", 2)
	if len(arrowParts) != 2 {
		return "", fmt.Errorf("invalid arrow syntax: %s", line)
	}
	domain := strings.TrimSpace(arrowParts[0])
	target := strings.TrimSpace(arrowParts[1])

	// Domain validation
	u, err := url.Parse("https://" + domain)
	if err != nil {
		return "", fmt.Errorf("%s: %v", domain, err)
	}
	if u.Port() != "" {
		return "", fmt.Errorf("%s: ports in domain names are not allowed - all domains are served through a single HTTPS port", domain)
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("%s: QUERY IN DOMAIN NOT YET REALIZED", domain) // TODO
	}

	// Ensure domain ends with slash. Need for lua-handler.go calls
	// TODO Why it need for lua-handler.go? WTF
	// Disabled due to bad findDomainInfo works
	// if !strings.HasPrefix(domain, "/") {
	// 	domain += "/"
	// }

	// Target validation
	if target == "" {
		return "", fmt.Errorf("empty target for domain: %s", domain)
	}

	// Output
	result := "-- " + line + "\n"
	result += fmt.Sprintf("AddRule(%q)\n", domain)

	if strings.Contains(target, "(") {
		// If target function - write as is
		result += fmt.Sprintf("Domains[%q].Target = %s\n", domain, target)
	} else {
		// Write in quotes
		result += fmt.Sprintf("Domains[%q].Target = %q\n", domain, target)
	}

	// Write options
	for _, opt := range optionsParts {
		if opt != "" {
			result += formatOption(domain, opt)
		}
	}

	return result, nil
}

func formatOption(domain, opt string) string {
	if strings.Contains(opt, "=") {
		// key = value
		parts := strings.SplitN(opt, "=", 2)
		return fmt.Sprintf("Domains[%q].%s = %s\n", domain, parts[0], parts[1])
	} else {
		// flag option: just method call
		if strings.Contains(opt, "(") {
			return fmt.Sprintf("Domains[%q]:%s\n", domain, opt)
		} else {
			// public  to  public()
			return fmt.Sprintf("Domains[%q]:%s()\n", domain, opt)
		}
	}
}
