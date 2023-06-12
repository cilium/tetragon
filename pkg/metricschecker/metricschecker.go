package metricschecker

import (
	"errors"
	"fmt"
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

func getMetricFamilies(text string) (map[string]*model.MetricFamily, error) {
	parser := expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	return families, nil
}

// CheckText runs a metrics check on a string.
func CheckText(checker MetricsChecker, text string) error {
	families, err := getMetricFamilies(text)
	if err != nil {
		return err
	}

	return checker.Check(families)
}

func getMetric(metrics map[string]*model.MetricFamily, name string) (*model.MetricFamily, error) {
	metric, ok := metrics[name]
	if !ok {
		return nil, fmt.Errorf("no such metric with label %s", name)
	}
	if metric == nil {
		return nil, fmt.Errorf("nil metric with label %s", name)
	}
	return metric, nil
}

type MetricsCheckError struct {
	// Name of the metric
	name string
	// Inner error(s)
	inner []error
}

func (e *MetricsCheckError) Error() string {
	return fmt.Sprintf("'%s' checks failed: %v", e.name, e.Inner())
}

func (e *MetricsCheckError) Inner() error {
	return errors.Join(e.inner...)
}
