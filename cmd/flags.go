package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// parseSize reads a size that is written as a Kubernetes quantity, such as 64Mi or 1Gi. The name is
// the name of the flag, for the message.
func parseSize(name, value string) (int64, error) {
	quantity, err := resource.ParseQuantity(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("--%s: %q is not a size such as 64Mi: %w", name, value, err)
	}
	if quantity.Sign() <= 0 {
		return 0, fmt.Errorf("--%s: %q must be more than zero", name, value)
	}
	return quantity.Value(), nil
}

// splitHosts reads a list of host names that are separated by commas. Spaces and empty items are
// ignored, so an empty value is an empty list. A name is a host such as github.com, or a domain with a
// wildcard in front such as *.example.com, and nothing that has a scheme or a path in it.
func splitHosts(list string) ([]string, error) {
	var hosts []string
	for item := range strings.SplitSeq(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.ContainsAny(item, "/:@ \t") || strings.Count(item, "*") > 1 ||
			(strings.Contains(item, "*") && !strings.HasPrefix(item, "*.")) {
			return nil, fmt.Errorf("--allowed-git-hosts: %q is not a host name such as github.com or *.example.com", item)
		}
		hosts = append(hosts, item)
	}
	return hosts, nil
}

// checkDurations refuses settings that cannot work together.
func checkDurations(gitTimeout, reconcileTimeout time.Duration) error {
	if gitTimeout <= 0 {
		return errors.New("--git-timeout must be more than zero")
	}
	if reconcileTimeout <= gitTimeout {
		return errors.New("--reconcile-timeout must be longer than --git-timeout, " +
			"or a fetch is cut short by the reconcile that waits for it")
	}
	return nil
}
