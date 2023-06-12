package metricschecker

import model "github.com/prometheus/client_model/go"

type CounterChecker struct {
	name   string
	checks []NumericMatcher[float64]
}

func NewCounterChecker(name string) *CounterChecker {
	return &CounterChecker{
		name:   name,
		checks: []NumericMatcher[float64]{},
	}
}

func (checker *CounterChecker) Check(metrics map[string]*model.MetricFamily) error {
	// metric, err := getMetric(metrics, checker.label)
	// if err != nil {
	// 	return err
	// }
	// for _, check := range checker.checks {
	// }
	return nil
}

func (checker *CounterChecker) WithMatcher(matcher NumericMatcher[float64]) {
	checker.checks = append(checker.checks, matcher)
}

func (checker *CounterChecker) WithMinimum(min float64) {
	checker.WithMatcher(GreaterThanOrEqual[float64](min))
}

func (checker *CounterChecker) WithMaximum(min float64) {
	checker.WithMatcher(LessThanOrEqual[float64](min))
}

func (checker *CounterChecker) WithRange(left, right float64) {
	checker.WithMatcher(Range[float64](left, right))
}
