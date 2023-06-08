package metricschecker

import (
	"io"
	"net/http"
	"strings"

	model "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// MetricsChecker is an interface for checking values of Tetragon metrics in tests.
type MetricsChecker interface {
	Check(metrics map[string]*model.MetricFamily) error
}

// Checker creates a new MultiMetricsChecker that wraps other metrics checkers.
func Checker(checkers ...MetricsChecker) MetricsChecker {
	return &MultiMetricsChecker{
		checkers,
	}
}

// CheckUrl runs a metrics check using a URL from which we fetch the metrics.
func CheckUrl(checker MetricsChecker, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return CheckText(checker, string(body))
}

// CheckText runs a metrics check on a string.
func CheckText(checker MetricsChecker, text string) error {
	parser := expfmt.TextParser{}
	metrics, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return err
	}

	return checker.Check(metrics)
}
