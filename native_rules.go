package asgsync

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type portSpan struct{ start, end uint16 }
type PortSpec []portSpan

func (p *PortSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		ports, err := parsePorts(n.Value)
		*p = ports
		return err
	case yaml.SequenceNode:
		var ports []uint16
		if err := n.Decode(&ports); err != nil {
			return err
		}
		for _, port := range ports {
			if port == 0 {
				return fmt.Errorf("ports must be between 1 and 65535")
			}
			*p = append(*p, portSpan{start: port})
		}
		return nil
	default:
		return fmt.Errorf("expected a port, comma-separated ports, a port range, or a list of ports")
	}
}

func parsePorts(raw string) (PortSpec, error) {
	var result PortSpec
	for _, s := range strings.Split(raw, ",") {
		first, last, rangePort := strings.Cut(s, "-")
		start, err := strconv.ParseUint(first, 10, 16)
		if err != nil || start == 0 {
			return nil, fmt.Errorf("invalid port %q", s)
		}
		span := portSpan{start: uint16(start)}
		if rangePort {
			if s != raw {
				return nil, fmt.Errorf("a port range cannot be combined with a list")
			}
			end, err := strconv.ParseUint(last, 10, 16)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid port range %q", s)
			}
			if end > start {
				span.end = uint16(end)
			}
		}
		result = append(result, span)
	}
	return result, nil
}

func destinationRules(destination, protocol string, ports PortSpec, typ, code *int, logRule bool) ([]Rule, error) {
	base := Rule{Protocol: protocol, Log: logRule}
	if logRule && protocol != "tcp" {
		return nil, fmt.Errorf("log requires tcp")
	}
	switch protocol {
	case "tcp", "udp":
		if len(ports) == 0 || typ != nil || code != nil {
			return nil, fmt.Errorf("%s requires ports and does not accept type or code", protocol)
		}
	case "icmp", "icmpv6":
		if len(ports) != 0 || typ == nil || code == nil || *typ < -1 || *typ > 255 || *code < -1 || *code > 255 {
			return nil, fmt.Errorf("%s requires type and code between -1 and 255 and does not accept ports", protocol)
		}
		base.Type, base.Code = *typ, *code
	case "all":
		if len(ports) != 0 || typ != nil || code != nil {
			return nil, fmt.Errorf("all does not accept ports, type, or code")
		}
	default:
		return nil, fmt.Errorf("invalid protocol %q", protocol)
	}
	var rules []Rule
	for _, dest := range strings.Split(destination, ",") {
		canonical, v6, err := canonicalDestination(dest)
		if err != nil {
			return nil, err
		}
		if protocol == "icmp" && v6 || protocol == "icmpv6" && !v6 {
			return nil, fmt.Errorf("destination %q has the wrong address family for %s", dest, protocol)
		}
		base.Destination = canonical
		if len(ports) == 0 {
			rules = append(rules, base)
		}
		for _, span := range ports {
			r := base
			r.Port, r.PortEnd = span.start, span.end
			rules = append(rules, r)
		}
	}
	return normalize(rules), nil
}

func canonicalDestination(dest string) (string, bool, error) {
	if a, err := netip.ParseAddr(dest); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return a.String(), a.Is6(), nil
	}
	if p, err := netip.ParsePrefix(dest); err == nil {
		if p.Bits() == p.Addr().BitLen() {
			a := p.Addr().Unmap()
			return a.String(), a.Is6(), nil
		}
		return p.Masked().String(), p.Addr().Is6(), nil
	}
	if first, last, ok := strings.Cut(dest, "-"); ok {
		a, e1 := netip.ParseAddr(first)
		b, e2 := netip.ParseAddr(last)
		if e1 == nil && e2 == nil && a.Zone() == "" && b.Zone() == "" && a.BitLen() == b.BitLen() && a.Compare(b) <= 0 {
			if a == b {
				a = a.Unmap()
				return a.String(), a.Is6(), nil
			}
			return a.String() + "-" + b.String(), a.Is6(), nil
		}
	}
	return "", false, fmt.Errorf("invalid ASG destination %q", dest)
}

func (r Rule) portString() string {
	if r.Port == 0 {
		return ""
	}
	p := strconv.Itoa(int(r.Port))
	if r.PortEnd != 0 {
		p += "-" + strconv.Itoa(int(r.PortEnd))
	}
	return p
}

func (r Rule) displayDestination() string {
	if p := r.portString(); p != "" {
		return r.Destination + " ports " + p
	}
	if r.Protocol == "icmp" || r.Protocol == "icmpv6" {
		return fmt.Sprintf("%s type %d code %d", r.Destination, r.Type, r.Code)
	}
	return r.Destination
}
