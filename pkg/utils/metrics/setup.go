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
	MetricAWSAPICallsRec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "aws_api_calls_reconcile_managed_resource",
		Help: "Amount of calls to the AWS API produced by controller per reconciliation for every managed resource and controller operation type",
	}, []string{"api_version", "kind", "resource_name", "controller_operation_type"})
	MetricManagedResRec = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "managed_resource_reconciles_total",
		Help: "Total amount of reconciliation loops per managed resource",
	}, []string{"api_version", "kind", "resource_name"})
)

// SetupMetrics will register the known Prometheus metrics with controller-runtime's metrics registry
func SetupMetrics() {
	k8smetrics.Registry.MustRegister(
		metricAWSAPICalls,
		MetricAWSAPICallsRec,
		MetricManagedResRec)
}

// IncAWSAPICall will increment the aws_api_calls_total metric for the specified service, operation, and apiVersion tuple
func IncAWSAPICall(service, operation, apiVersion string) {
	metricAWSAPICalls.WithLabelValues(service, operation, apiVersion).Inc()
}
