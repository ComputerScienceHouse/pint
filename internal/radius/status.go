// internal/radius/status.go
package radius

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	metricsv "k8s.io/metrics/pkg/client/clientset/versioned"
)

const logTailLines = 200

// DeploymentStatus summarizes the FreeRADIUS deployment for display.
type DeploymentStatus struct {
	Name            string
	DesiredReplicas int32
	ReadyReplicas   int32
	Image           string
	LastRestartedAt string // value of kubectl.kubernetes.io/restartedAt annotation, empty if unset
	Pods            []PodStatus
	Events          []K8sEvent
}

// StatusServerConfig holds the status virtual server configuration.
type StatusServerConfig struct {
	Port   string
	Secret string
	CIDR   string
}

// PodStatus holds per-pod health info and recent log output.
type PodStatus struct {
	Name         string
	Phase        string
	Ready        bool
	RestartCount int32
	StartTime    string // RFC1123
	Uptime       string // human-readable duration
	Requests     ResourceUsage  // from pod spec; always populated
	Limits       ResourceUsage  // from pod spec; empty strings where unset
	Usage        *ResourceUsage // nil if metrics-server unavailable
	Stats        *RADIUSStats   // nil if status server unreachable or not configured
	Logs         string
}

// ResourceUsage holds formatted CPU and memory values (usage, requests, or limits).
type ResourceUsage struct {
	CPU    string // empty string means unset
	Memory string // empty string means unset
}

// K8sEvent is a single Kubernetes Warning event related to the deployment or its pods.
type K8sEvent struct {
	Reason   string
	Message  string
	Count    int32
	LastSeen string // RFC1123
}

// CertInfo holds key fields from the FreeRADIUS server TLS certificate.
type CertInfo struct {
	Subject    string
	Expiry     string // RFC1123
	DaysLeft   int
	IsExpired  bool
	NearExpiry bool // within 30 days
}

// GetStatus fetches deployment health, per-pod details and logs, and Warning events.
// metricsClient may be nil; if so, pod resource usage is omitted.
// statusPort and statusSecret are used to query the FreeRADIUS status virtual server per pod;
// pass empty strings to skip (graceful degradation when the status server is not accessible).
// statusAddrOverride, when non-empty, replaces the per-pod IP for all status queries (useful
// when pod IPs are unreachable, e.g. running pint outside a kind cluster on macOS).
func GetStatus(ctx context.Context, k8s kubernetes.Interface, metricsClient metricsv.Interface, namespace, deployment, statusPort, statusSecret, statusAddrOverride string) (*DeploymentStatus, error) {
	dep, err := k8s.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get deployment %s: %w", deployment, err)
	}

	desired := int32(1)
	if dep.Spec.Replicas != nil {
		desired = *dep.Spec.Replicas
	}

	image := ""
	if len(dep.Spec.Template.Spec.Containers) > 0 {
		image = dep.Spec.Template.Spec.Containers[0].Image
	}

	status := &DeploymentStatus{
		Name:            dep.Name,
		DesiredReplicas: desired,
		ReadyReplicas:   dep.Status.ReadyReplicas,
		Image:           image,
		LastRestartedAt: dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"],
	}

	labelSelector := labels.Set(dep.Spec.Selector.MatchLabels).String()
	pods, err := k8s.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		// Non-fatal: return deployment-level info without pod details.
		return status, nil
	}

	podNames := make(map[string]bool, len(pods.Items))
	podStatuses := make([]PodStatus, len(pods.Items))
	var wg sync.WaitGroup
	for i, pod := range pods.Items {
		podNames[pod.Name] = true
		wg.Add(1)
		go func(i int, pod corev1.Pod) {
			defer wg.Done()
			ps := PodStatus{
				Name:  pod.Name,
				Phase: string(pod.Status.Phase),
			}
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady {
					ps.Ready = cond.Status == corev1.ConditionTrue
				}
			}
			for _, cs := range pod.Status.ContainerStatuses {
				ps.RestartCount += cs.RestartCount
			}
			var cpuReq, cpuLim, memReq, memLim resource.Quantity
			for _, c := range pod.Spec.Containers {
				if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
					cpuReq.Add(q)
				}
				if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
					cpuLim.Add(q)
				}
				if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
					memReq.Add(q)
				}
				if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
					memLim.Add(q)
				}
			}
			ps.Requests = ResourceUsage{
				CPU:    formatCPUIfNonZero(cpuReq),
				Memory: formatMemoryIfNonZero(memReq),
			}
			ps.Limits = ResourceUsage{
				CPU:    formatCPUIfNonZero(cpuLim),
				Memory: formatMemoryIfNonZero(memLim),
			}
			if pod.Status.StartTime != nil {
				ps.StartTime = pod.Status.StartTime.UTC().Format(time.RFC1123)
				ps.Uptime = formatDuration(time.Since(pod.Status.StartTime.Time))
			}
			ps.Logs = fetchPodLogs(ctx, k8s, namespace, pod.Name)
			if statusPort != "" && statusSecret != "" && pod.Status.PodIP != "" {
				addr := pod.Status.PodIP + ":" + statusPort
				if statusAddrOverride != "" {
					addr = statusAddrOverride
				}
				ps.Stats = QueryRADIUSStats(ctx, addr, statusSecret)
			}
			podStatuses[i] = ps
		}(i, pod)
	}
	wg.Wait()
	status.Pods = podStatuses

	// Pod resource usage from metrics-server (best-effort; skip if unavailable).
	if metricsClient != nil {
		podMetrics, merr := metricsClient.MetricsV1beta1().PodMetricses(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if merr == nil {
			usageByName := make(map[string]ResourceUsage, len(podMetrics.Items))
			for _, pm := range podMetrics.Items {
				var cpu, mem resource.Quantity
				for _, c := range pm.Containers {
					cpuQ := c.Usage[corev1.ResourceCPU]
					memQ := c.Usage[corev1.ResourceMemory]
					cpu.Add(cpuQ)
					mem.Add(memQ)
				}
				usageByName[pm.Name] = ResourceUsage{
					CPU:    formatCPU(cpu),
					Memory: formatMemory(mem),
				}
			}
			for i, ps := range status.Pods {
				if u, ok := usageByName[ps.Name]; ok {
					status.Pods[i].Usage = &u
				}
			}
		}
	}

	// Warning events for the deployment and its pods (one API call).
	evList, err := k8s.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "type=Warning",
	})
	if err == nil {
		for _, ev := range evList.Items {
			name := ev.InvolvedObject.Name
			if name != deployment && !podNames[name] {
				continue
			}
			status.Events = append(status.Events, K8sEvent{
				Reason:   ev.Reason,
				Message:  ev.Message,
				Count:    ev.Count,
				LastSeen: ev.LastTimestamp.UTC().Format(time.RFC1123),
			})
		}
	}

	return status, nil
}

// GetCertInfo reads a PEM certificate from the named key in the named K8s Secret
// and returns display-ready expiry information.
func GetCertInfo(ctx context.Context, k8s kubernetes.Interface, namespace, secretName, key string) (*CertInfo, error) {
	secret, err := k8s.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %s: %w", secretName, err)
	}
	pemData, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("%s not found in secret %s", key, secretName)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM in secret %s", secretName)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return &CertInfo{
		Subject:    cert.Subject.CommonName,
		Expiry:     cert.NotAfter.UTC().Format(time.RFC1123),
		DaysLeft:   daysLeft,
		IsExpired:  daysLeft < 0,
		NearExpiry: daysLeft >= 0 && daysLeft <= 30,
	}, nil
}

func fetchPodLogs(ctx context.Context, k8s kubernetes.Interface, namespace, podName string) string {
	tail := int64(logTailLines)
	stream, err := k8s.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		TailLines: &tail,
	}).Stream(ctx)
	if err != nil {
		return fmt.Sprintf("(error fetching logs: %v)", err)
	}
	defer stream.Close()
	data, err := io.ReadAll(stream)
	if err != nil {
		return "(error reading logs)"
	}
	return string(data)
}

func formatCPUIfNonZero(q resource.Quantity) string {
	if q.IsZero() {
		return ""
	}
	return formatCPU(q)
}

func formatMemoryIfNonZero(q resource.Quantity) string {
	if q.IsZero() {
		return ""
	}
	return formatMemory(q)
}

func formatCPU(q resource.Quantity) string {
	m := q.MilliValue()
	if m < 1000 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%.2f", float64(m)/1000)
}

func formatMemory(q resource.Quantity) string {
	b := q.Value()
	switch {
	case b < 1024*1024:
		return fmt.Sprintf("%dKi", b/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.0fMi", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.2fGi", float64(b)/(1024*1024*1024))
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}
