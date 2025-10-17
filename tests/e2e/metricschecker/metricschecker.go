//go:build !windows

package metricschecker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	clmo "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/tests/e2e/state"
)

// MetricsChecker checks prometheus metrics from one or more events streams.
type MetricsChecker struct {
	name      string
	timeLimit time.Duration
}

// NewMetricsChecker constructs a new Metrics from a MultiEventChecker.
func NewMetricsChecker(name string) *MetricsChecker {
	rc := &MetricsChecker{
		name:      name,
		timeLimit: 30 * time.Second,
	}
	return rc
}

// WithTimeLimit sets the time limit for a MetricsChecker http GET calls.
func (rc *MetricsChecker) WithTimeLimit(limit time.Duration) *MetricsChecker {
	rc.timeLimit = limit
	return rc
}

type metricOp int

const (
	opEqual   metricOp = 1
	opGreater          = 1 << iota
	opLess
)

type metricValue struct {
	tp  clmo.MetricType
	val float64
}
type metricCheck struct {
	value metricValue
	op    metricOp
}

func (rc *MetricsChecker) Equal(metric string, val int) features.Func {
	return rc.checkWithOp(metric, metricCheck{
		value: metricValue{
			tp:  clmo.MetricType_COUNTER,
			val: float64(val),
		},
		op: opEqual,
	})
}

func (rc *MetricsChecker) Less(metric string, val int) features.Func {
	return rc.checkWithOp(metric, metricCheck{
		value: metricValue{
			tp:  clmo.MetricType_COUNTER,
			val: float64(val),
		},
		op: opLess,
	})
}

func (rc *MetricsChecker) LessThanOrEqual(metric string, val int) features.Func {
	return rc.checkWithOp(metric, metricCheck{
		value: metricValue{
			tp:  clmo.MetricType_COUNTER,
			val: float64(val),
		},
		op: opEqual | opLess,
	})
}

func (rc *MetricsChecker) Greater(metric string, val int) features.Func {
	return rc.checkWithOp(metric, metricCheck{
		value: metricValue{
			tp:  clmo.MetricType_COUNTER,
			val: float64(val),
		},
		op: opGreater,
	})
}

func (rc *MetricsChecker) GreaterOrEqual(metric string, val int) features.Func {
	return rc.checkWithOp(metric, metricCheck{
		value: metricValue{
			tp:  clmo.MetricType_COUNTER,
			val: float64(val),
		},
		op: opEqual | opGreater,
	})
}

// getAndParseMetrics fetches metrics from a URL and parses them into MetricFamily objects.
func getAndParseMetrics(ctx context.Context, metricsURL string) (map[string]*clmo.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics from %s: %w", metricsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK status code %d from %s", resp.StatusCode, metricsURL)
	}

	parser := expfmt.NewTextParser(model.UTF8Validation)
	mf, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics body: %w", err)
	}
	return mf, nil
}

// Collect metrics from all forwarded metrics ports for all pods
func (rc *MetricsChecker) checkWithOp(metric string, check metricCheck) features.Func {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		klog.InfoS("Gathering metrics clients", "metricschecker", rc.name)
		ports, ok := ctx.Value(state.PromForwardedPorts).(map[string]int)
		if !ok {
			assert.Fail(t, "failed to find forwarded prometheus ports")
			return ctx
		}

		timedCtx, cancel := context.WithTimeout(ctx, rc.timeLimit)
		defer cancel()

		results := make(map[string]*clmo.MetricFamily)
		for podName, port := range ports {
			metricFamilies, err := getAndParseMetrics(timedCtx, fmt.Sprintf("http://localhost:%d/metrics", port))
			if err != nil {
				assert.Fail(t, "Failed to fetch metrics families from metrics endpoint", "err", err, "podName", podName)
				return ctx
			}

			if mf, ok := metricFamilies[metric]; ok {
				results[podName] = mf
			} else {
				klog.InfoS("No metric found on pod", "metricschecker", rc.name, "metric", metric, "podName", podName)
			}
		}

		// No metrics endpoint exported the requested metric. This is an error.
		if len(results) == 0 {
			assert.Fail(t, "Failed to fetch requested metrics from any pod", "metricName", metric)
			return ctx
		}

		if err := rc.check(results, metric, check); !assert.NoError(t, err, "checks should pass") {
			return ctx
		}
		return ctx
	}
}

// Real check helper that implements the check logic for each metric type.
// For now, only COUNTER types are supported.
func (rc *MetricsChecker) check(results map[string]*clmo.MetricFamily, metric string, check metricCheck) error {
	klog.InfoS("Running metrics checks", "metricschecker", rc.name)

	for podName, result := range results {
		if result.GetType() != check.value.tp {
			return errors.New("result type and check type mismatch")
		}
		switch result.GetType() {
		case clmo.MetricType_COUNTER:
			var sum float64
			// Accumulate values from all labels
			for _, mf := range result.GetMetric() {
				sum += mf.GetCounter().GetValue()
			}

			success := false
			if check.op&opEqual != 0 {
				success = sum == check.value.val
			}
			if check.op&opGreater != 0 {
				success = success || (sum > check.value.val)
			}
			if check.op&opLess != 0 {
				success = success || (sum < check.value.val)
			}
			if !success {
				return fmt.Errorf("failed metricscheck for metric '%s' on pod '%s'", metric, podName)
			}
		default:
			// TODO implement check logic for non-counter types
			return errors.New("metrics checker unsupported for non-counter types")
		}
	}
	return nil
}

// Name returns the name of the checker
func (rc *MetricsChecker) Name() string {
	return rc.name
}
