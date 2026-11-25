package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The four classes of literal, most specific first: a finding of an earlier
// class owns its span of the line, so `postgres://u@localhost:5432/db` is one
// DSN and not also a host:port.
const (
	classDSN      = "dsn"
	classURL      = "url"
	classHostPort = "hostport"
	classPort     = "port"
)

// finding is one literal on one line.
type finding struct {
	path    string
	line    int
	class   string
	literal string
	kind    string
}

var (
	// A connection string of a store or a broker. Whatever follows the scheme
	// up to a space, a quote or an angle bracket is the literal; nothing
	// following it is a bare scheme, which names no address.
	dsnPattern = regexp.MustCompile(`\b(?:postgresql|postgres|rediss|redis|clickhouse|mysql|mongodb|amqp|nats)://[^\s"'` + "`" + `<>]*`)

	// An HTTP URL that names a port.
	urlPattern = regexp.MustCompile(`\bhttps?://([A-Za-z0-9_.-]+|\[[0-9A-Fa-f:.]+\]):([0-9]+)`)

	// A loopback, wildcard or docker-host address with a port.
	hostPortPattern = regexp.MustCompile(`(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal):([0-9]+)`)

	// A port assigned to a name: `port: 8080`, `PORT=3000`, `containerPort:
	// 8080`, `defaultPort = 9090`, `"port": 5432`. The name is `port` as a
	// word, after an underscore, or as a capitalised part of a camel-case
	// name, so `report: 500` and `transport = 100` are not ports.
	portAssignPattern = regexp.MustCompile(`(?:(?:\b|_)(?:port|PORT|Port)|[a-z0-9]Port)(?:s|S|_[A-Za-z0-9_]*|[A-Z][A-Za-z0-9_]*)?["']?\s*(?::=|=|:)\s*["']?([1-9][0-9]{1,4})`)

	// A port passed as a flag: `--port 8080`, `--port=8080`, `"--port", "8080"`.
	portFlagPattern = regexp.MustCompile(`--port(?:=|\s+|["']\s*,\s*["'])["']?([1-9][0-9]{1,4})`)

	// A published container port: `docker run -p 9000:9000`.
	publishPattern = regexp.MustCompile(`(?:^|\s)-p\s+["']?([0-9]+):([0-9]+)`)

	// A Dockerfile EXPOSE, which may name several ports.
	exposePattern     = regexp.MustCompile(`^\s*EXPOSE\s+(.+)$`)
	exposePortPattern = regexp.MustCompile(`^([1-9][0-9]*)(?:/[a-z]+)?$`)

	// A listen address with no host: `":8080"` on its own (four or five
	// digits, so `":30"` in a time format is not one), and any port given
	// straight to a Listen call.
	listenLiteralPattern = regexp.MustCompile(`["'` + "`" + `](:[1-9][0-9]{3,4})["'` + "`" + `]`)
	listenCallPattern    = regexp.MustCompile(`Listen(?:AndServe(?:TLS)?)?\((?:"tcp[46]?",\s*)?"(:[1-9][0-9]*)`)
)

// candidate is a literal found on a line, with the span it occupies.
type candidate struct {
	start, end int
	class      string
	literal    string
	legitimate bool
}

// scan returns every finding in a file's content. A literal that is legitimate
// on its face (port 0, a sentinel, a reserved name) is not returned, and it
// still owns its span, so its parts are not reported under another class.
func scan(path, content string) []finding {
	kind := kindOf(path)
	var findings []finding
	for index, line := range strings.Split(content, "\n") {
		line = strings.TrimSuffix(line, "\r")
		candidates := candidatesOf(line)
		if len(candidates) == 0 {
			continue
		}
		var owned []candidate
		seen := map[string]bool{}
		for _, found := range candidates {
			if overlaps(owned, found) {
				continue
			}
			owned = append(owned, found)
			key := found.class + "\x00" + found.literal
			if found.legitimate || seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, finding{path: path, line: index + 1, class: found.class, literal: found.literal, kind: kind})
		}
	}
	return findings
}

func overlaps(owned []candidate, found candidate) bool {
	for _, other := range owned {
		if found.start < other.end && other.start < found.end {
			return true
		}
	}
	return false
}

// classRank orders candidates so the most specific class claims a span first.
var classRank = map[string]int{classDSN: 0, classURL: 1, classHostPort: 2, classPort: 3}

func candidatesOf(line string) []candidate {
	var found []candidate
	hasScheme := strings.Contains(line, "://")

	if hasScheme {
		for _, span := range dsnPattern.FindAllStringIndex(line, -1) {
			literal := strings.TrimRight(line[span[0]:span[1]], ").,;]}")
			found = append(found, candidate{
				start: span[0], end: span[0] + len(literal), class: classDSN,
				literal: literal, legitimate: legitimateDSN(literal),
			})
		}
		for _, span := range urlPattern.FindAllStringSubmatchIndex(line, -1) {
			host, port := line[span[2]:span[3]], line[span[4]:span[5]]
			number, isPort := portNumber(port)
			if !isPort {
				continue
			}
			found = append(found, candidate{
				start: span[0], end: span[1], class: classURL, literal: line[span[0]:span[1]],
				legitimate: number == 0 || reservedHost(host) || sentinel(host, number),
			})
		}
	}

	if strings.Contains(line, "localhost") || strings.Contains(line, "0.0.") || strings.Contains(line, "::1") || strings.Contains(line, "host.docker") {
		for _, span := range hostPortPattern.FindAllStringSubmatchIndex(line, -1) {
			// `my.localhost:80` and `10.127.0.0.1:80` are other hosts.
			if span[0] > 0 && hostCharacter(line[span[0]-1]) {
				continue
			}
			host, port := line[span[2]:span[3]], line[span[4]:span[5]]
			number, isPort := portNumber(port)
			if !isPort {
				continue
			}
			found = append(found, candidate{
				start: span[0], end: span[1], class: classHostPort, literal: line[span[0]:span[1]],
				legitimate: number == 0 || sentinel(host, number),
			})
		}
	}

	if strings.Contains(line, "ort") || strings.Contains(line, "ORT") {
		for _, span := range portAssignPattern.FindAllStringSubmatchIndex(line, -1) {
			found = appendPort(found, line, span[2], span[3], "")
		}
		for _, span := range portFlagPattern.FindAllStringSubmatchIndex(line, -1) {
			found = appendPort(found, line, span[2], span[3], "")
		}
	}
	if strings.Contains(line, "-p") {
		for _, span := range publishPattern.FindAllStringSubmatchIndex(line, -1) {
			host, hostIsPort := portNumber(line[span[2]:span[3]])
			_, containerIsPort := portNumber(line[span[4]:span[5]])
			if !hostIsPort || !containerIsPort || trailsNumber(line, span[5]) {
				continue
			}
			// Host port 0 asks the system for one.
			found = append(found, candidate{
				start: span[2], end: span[5], class: classPort, literal: line[span[2]:span[5]], legitimate: host == 0,
			})
		}
	}
	if strings.Contains(line, "EXPOSE") {
		if span := exposePattern.FindStringSubmatchIndex(line); span != nil {
			offset := span[2]
			for _, field := range strings.Fields(line[span[2]:span[3]]) {
				start := offset + strings.Index(line[offset:], field)
				offset = start + len(field)
				if match := exposePortPattern.FindStringSubmatch(field); match != nil {
					found = appendPort(found, line, start, start+len(match[1]), "")
				}
			}
		}
	}
	if strings.Contains(line, ":") {
		for _, span := range listenLiteralPattern.FindAllStringSubmatchIndex(line, -1) {
			found = appendPort(found, line, span[2], span[3], ":")
		}
		if strings.Contains(line, "Listen") {
			for _, span := range listenCallPattern.FindAllStringSubmatchIndex(line, -1) {
				found = appendPort(found, line, span[2], span[3], ":")
			}
		}
	}

	sort.SliceStable(found, func(i, j int) bool {
		if classRank[found[i].class] != classRank[found[j].class] {
			return classRank[found[i].class] < classRank[found[j].class]
		}
		return found[i].start < found[j].start
	})
	return found
}

// appendPort adds the port literal at line[start:end] when it is a port number
// that is not the start of a longer number or a decimal. prefix is what the
// literal carries before its digits (":" for a listen address).
func appendPort(found []candidate, line string, start, end int, prefix string) []candidate {
	if _, isPort := portNumber(strings.TrimPrefix(line[start:end], prefix)); !isPort || trailsNumber(line, end) {
		return found
	}
	return append(found, candidate{start: start, end: end, class: classPort, literal: line[start:end]})
}

// trailsNumber reports that the digits ending at end continue: another digit,
// or a decimal point followed by one (8080.5, 127.0.0.1).
func trailsNumber(line string, end int) bool {
	if end >= len(line) {
		return false
	}
	if digit(line[end]) {
		return true
	}
	return line[end] == '.' && end+1 < len(line) && digit(line[end+1])
}

func digit(character byte) bool { return character >= '0' && character <= '9' }

func hostCharacter(character byte) bool {
	return digit(character) || character == '.' || character == '-' || character == '_' ||
		(character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

// portNumber parses digits as a TCP port.
func portNumber(digits string) (int, bool) {
	if digits == "" || len(digits) > 5 {
		return 0, false
	}
	number, err := strconv.Atoi(digits)
	if err != nil || number > 65535 {
		return 0, false
	}
	return number, true
}

// sentinel reports the two addresses that are written to never connect.
func sentinel(host string, port int) bool {
	return (host == "127.0.0.1" && port == 1) || (host == "localhost" && port == 9)
}

// reservedHost reports a name or address reserved for documentation and
// tests, which resolves to nothing: RFC 2606 and RFC 6761 names, RFC 5737
// addresses.
func reservedHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, name := range []string{"invalid", "test", "example", "example.com", "example.org", "example.net"} {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		if last, ok := strings.CutPrefix(host, prefix); ok {
			if number, isNumber := portNumber(last); isNumber && number <= 255 {
				return true
			}
		}
	}
	return false
}

// legitimateDSN reports a connection string that names no address a process
// could dial: a bare scheme, a reserved host, a sentinel, or port 0.
func legitimateDSN(literal string) bool {
	_, rest, _ := strings.Cut(literal, "://")
	if rest == "" {
		return true
	}
	authority := rest
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	host, port := authority, ""
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end >= 0 {
			host, port = authority[:end+1], strings.TrimPrefix(authority[end+1:], ":")
		}
	} else if colon := strings.LastIndex(authority, ":"); colon >= 0 {
		host, port = authority[:colon], authority[colon+1:]
	}
	if reservedHost(host) {
		return true
	}
	number, isPort := portNumber(port)
	return isPort && (number == 0 || sentinel(host, number))
}
