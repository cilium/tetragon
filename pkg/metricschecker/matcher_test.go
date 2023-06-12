package metricschecker_test

import (
	"testing"

	"github.com/cilium/tetragon/pkg/metricschecker"
	"github.com/stretchr/testify/assert"
)

type TestCase[N metricschecker.Number] struct {
	name        string
	matcher     metricschecker.NumericMatcher[N]
	val         N
	expectedErr bool
}

func (tc *TestCase[N]) Run(t *testing.T) {
	err := tc.matcher.Match(tc.val)
	if tc.expectedErr {
		assert.Error(t, err, "match should fail")
	} else {
		assert.NoError(t, err, "match should succeed")
	}
}

func TestNumericMatchersInt32(t *testing.T) {
	testCases := []TestCase[int32]{
		{
			name:        "lessThanGood",
			matcher:     metricschecker.LessThan[int32](13),
			val:         12,
			expectedErr: false,
		},
		{
			name:        "lessThanBad1",
			matcher:     metricschecker.LessThan[int32](13),
			val:         13,
			expectedErr: true,
		},
		{
			name:        "lessThanBad2",
			matcher:     metricschecker.LessThan[int32](13),
			val:         14,
			expectedErr: true,
		},
		{
			name:        "lessThanOrEqualGood1",
			matcher:     metricschecker.LessThanOrEqual[int32](13),
			val:         12,
			expectedErr: false,
		},
		{
			name:        "lessThanOrEqualGood2",
			matcher:     metricschecker.LessThanOrEqual[int32](13),
			val:         13,
			expectedErr: false,
		},
		{
			name:        "lessThanOrEqualBad",
			matcher:     metricschecker.LessThanOrEqual[int32](13),
			val:         14,
			expectedErr: true,
		},
		{
			name:        "greaterThanGood",
			matcher:     metricschecker.GreaterThan[int32](13),
			val:         14,
			expectedErr: false,
		},
		{
			name:        "greaterThanBad1",
			matcher:     metricschecker.GreaterThan[int32](13),
			val:         13,
			expectedErr: true,
		},
		{
			name:        "greaterThanBad2",
			matcher:     metricschecker.GreaterThan[int32](13),
			val:         12,
			expectedErr: true,
		},
		{
			name:        "greaterThanOrEqualGood1",
			matcher:     metricschecker.GreaterThanOrEqual[int32](13),
			val:         14,
			expectedErr: false,
		},
		{
			name:        "greaterThanOrEqualGood2",
			matcher:     metricschecker.GreaterThanOrEqual[int32](13),
			val:         13,
			expectedErr: false,
		},
		{
			name:        "greaterThanOrEqualBad",
			matcher:     metricschecker.GreaterThanOrEqual[int32](13),
			val:         12,
			expectedErr: true,
		},
		{
			name:        "equalGood",
			matcher:     metricschecker.Equal[int32](13),
			val:         13,
			expectedErr: false,
		},
		{
			name:        "equalBad",
			matcher:     metricschecker.Equal[int32](13),
			val:         12,
			expectedErr: true,
		},
		{
			name:        "rangeGood1",
			matcher:     metricschecker.Range[int32](0, 13),
			val:         12,
			expectedErr: false,
		},
		{
			name:        "rangeGood2",
			matcher:     metricschecker.Range[int32](0, 13),
			val:         0,
			expectedErr: false,
		},
		{
			name:        "rangeBad1",
			matcher:     metricschecker.Range[int32](0, 13),
			val:         13,
			expectedErr: true,
		},
		{
			name:        "rangeBad2",
			matcher:     metricschecker.Range[int32](0, 13),
			val:         14,
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.Run)
	}
}
