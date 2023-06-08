package metricschecker

import (
	"errors"
	"fmt"

	model "github.com/prometheus/client_model/go"
)

type MultiMetricsChecker struct {
	checkers []MetricsChecker
}

func (m *MultiMetricsChecker) Check(metrics map[string]*model.MetricFamily) error {
	var errs []error

	for _, check := range m.checkers {
		if err := check.Check(metrics); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return &MultiMetricsCheckError{
			inner: errs,
		}
	}

	return nil
}

type MultiMetricsCheckError struct {
	inner []error
}

func (e *MultiMetricsCheckError) Error() string {
	return fmt.Sprintf("multiple metrics checks failed: %v", e.Inner())
}

func (e *MultiMetricsCheckError) Inner() error {
	return errors.Join(e.inner...)
}
