package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	k8smetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	metricAWSAPICalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "aws_api_calls_total",
		Help: "Number of API calls to the AWS API",
	}, []string{"service", "operation", "api_version"})
	MetricAWSAPIRecCalls = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aws_api_reconciliation_calls",
		Help: "Number of calls of the AWS API produced by controller to provide reconciliation per managed resource and operation type",
	}, []string{"service", "resource_group", "resource_name", "controller_operation_type"})
)

// SetupMetrics will register the known Prometheus metrics with controller-runtime's metrics registry
func SetupMetrics() {
	k8smetrics.Registry.MustRegister(
		metricAWSAPICalls,
		MetricAWSAPIRecCalls)
}

// IncAWSAPICall will increment the aws_api_calls_total metric for the specified service, operation, and apiVersion tuple
func IncAWSAPICall(service, operation, apiVersion string) {
	metricAWSAPICalls.WithLabelValues(service, operation, apiVersion).Inc()
}
