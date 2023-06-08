package metricschecker

import (
	"fmt"

	"golang.org/x/exp/constraints"
)

type Number interface {
	constraints.Integer | constraints.Float
}

type NumericMatcher[N Number] interface {
	Match(actual N) error
}

type FnNumericMatcher[N Number] func(n N) error

func (f FnNumericMatcher[N]) Match(actual N) error {
	return f(actual)
}

func LessThan[N Number](expected N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual < expected {
			return nil
		}
		return fmt.Errorf("expected %v < %v", actual, expected)
	}
}

func GreaterThan[N Number](expected N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual > expected {
			return nil
		}
		return fmt.Errorf("expected %v > %v", actual, expected)
	}
}

func LessThanOrEqual[N Number](expected N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual <= expected {
			return nil
		}
		return fmt.Errorf("expected %v <= %v", actual, expected)
	}
}

func GreaterThanOrEqual[N Number](expected N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual >= expected {
			return nil
		}
		return fmt.Errorf("expected %v >= %v", actual, expected)
	}
}

func Equal[N Number](expected N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual == expected {
			return nil
		}
		return fmt.Errorf("expected %v == %v", actual, expected)
	}
}

func Range[N Number](left, right N) FnNumericMatcher[N] {
	return func(actual N) error {
		if actual >= left && actual < right {
			return nil
		}
		return fmt.Errorf("expected %v to be within range [%v, %v)", actual, left, right)
	}
}
