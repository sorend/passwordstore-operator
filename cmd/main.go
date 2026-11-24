package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/controller"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	// version and commit are set when the binary is built, see the Dockerfile.
	version = "dev"
	commit  = "unknown"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(passwordstorev1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var webhookPort int
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	var gitTimeout, gitCooldown, storeSyncInterval, retryInterval, reconcileTimeout time.Duration
	var maxConcurrentReconciles int
	var gitMaxRepositorySize, gitCacheSize, allowedGitHosts string
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Port the webhook server listens on. "+
		"Defaults to 9443. Set -1 to disable the webhook server.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.DurationVar(&gitTimeout, "git-timeout", gitstore.DefaultTimeout,
		"The time that one fetch from a Git repository may take, including the exchange of a GitHub App token.")
	flag.StringVar(&gitMaxRepositorySize, "git-max-repository-size", "64Mi",
		"The most that a Git repository may take in memory, after it is decompressed, as a quantity such as 64Mi. "+
			"A repository that is larger is refused.")
	flag.StringVar(&gitCacheSize, "git-cache-size", "128Mi",
		"The most that all the repositories that are kept may take in memory together, as a quantity. The ones that "+
			"were used least are dropped to make room. It is raised to the size of one repository when it is less.")
	flag.StringVar(&allowedGitHosts, "allowed-git-hosts", "",
		"A comma-separated list of the hosts that the operator may connect to, for repositories and for the API of "+
			"GitHub, such as github.com,*.example.com. A wildcard stands for what is below a domain. When it is empty "+
			"any host is allowed, except for loopback and link-local addresses, which never are.")
	flag.DurationVar(&reconcileTimeout, "reconcile-timeout", controller.DefaultReconciliationTimeout,
		"How long one reconcile may take. It must be longer than --git-timeout.")
	flag.DurationVar(&gitCooldown, "git-cooldown", controller.DefaultFetchCooldown,
		"The time within which a PasswordStoreSecret reuses the last check of its repository instead of contacting "+
			"the Git server again. Use 0 to contact the server on every refresh.")
	flag.DurationVar(&storeSyncInterval, "store-sync-interval", controller.DefaultStoreSyncInterval,
		"How often a PasswordStore or ClusterPasswordStore checks its repository, and reports the result in its status, "+
			"without being asked to by a PasswordStoreSecret.")
	flag.DurationVar(&retryInterval, "retry-interval", controller.DefaultRetryInterval,
		"How soon a resource that could not be reconciled is tried again.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", controller.DefaultMaxConcurrentReconciles,
		"The number of resources that each controller reconciles at the same time.")
	// Logs are JSON at info level. Use --zap-devel for the console format and debug level.
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog.Info("Starting passwordstore-operator", "version", version, "commit", commit)

	maxRepositoryBytes, err := parseSize("git-max-repository-size", gitMaxRepositorySize)
	if err != nil {
		setupLog.Error(err, "Invalid flag")
		os.Exit(1)
	}
	cacheBytes, err := parseSize("git-cache-size", gitCacheSize)
	if err != nil {
		setupLog.Error(err, "Invalid flag")
		os.Exit(1)
	}
	hosts, err := splitHosts(allowedGitHosts)
	if err != nil {
		setupLog.Error(err, "Invalid flag")
		os.Exit(1)
	}
	if err := checkDurations(gitTimeout, reconcileTimeout); err != nil {
		setupLog.Error(err, "Invalid flags")
		os.Exit(1)
	}
	setupLog.Info("Limits for Git repositories", "timeout", gitTimeout.String(), "maxRepositoryBytes", maxRepositoryBytes,
		"cacheBytes", max(cacheBytes, maxRepositoryBytes), "allowedHosts", hosts)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
		Port:    webhookPort,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsServerOptions,
		// Secrets are always read straight from the API server, and only the ones that are
		// needed. Caching them would hold every Secret of the cluster in the memory of the operator.
		Client:                 client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "a2569f95.k8s.sorend.github.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	options := controller.Options{
		Git: gitstore.NewManager(gitstore.Options{
			Timeout:            gitTimeout,
			MaxRepositoryBytes: maxRepositoryBytes,
			CacheBytes:         cacheBytes,
			AllowedHosts:       hosts,
		}),
		StoreSyncInterval:       storeSyncInterval,
		RetryInterval:           retryInterval,
		FetchCooldown:           gitCooldown,
		MaxConcurrentReconciles: maxConcurrentReconciles,
		ReconciliationTimeout:   reconcileTimeout,
	}
	if err := (&controller.PasswordStoreReconciler{
		Client:   mgr.GetClient(),
		Reader:   mgr.GetAPIReader(),
		Recorder: mgr.GetEventRecorder("passwordstore-controller"),
		Options:  options,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "passwordstore")
		os.Exit(1)
	}
	if err := (&controller.PasswordStoreSecretReconciler{
		Client:   mgr.GetClient(),
		Reader:   mgr.GetAPIReader(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("passwordstoresecret-controller"),
		Options:  options,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "passwordstoresecret")
		os.Exit(1)
	}
	if err := (&controller.ClusterPasswordStoreReconciler{
		Client:   mgr.GetClient(),
		Reader:   mgr.GetAPIReader(),
		Recorder: mgr.GetEventRecorder("clusterpasswordstore-controller"),
		Options:  options,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "clusterpasswordstore")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
