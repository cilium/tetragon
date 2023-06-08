package metricschecker

type CounterChecker[N Number] struct {
	label  string
	checks []NumericMatcher[N]
}

func NewCounterChecker[N Number](label string) *CounterChecker[N] {
	return &CounterChecker[N]{
		label:  label,
		checks: []NumericMatcher[N]{},
	}
}
