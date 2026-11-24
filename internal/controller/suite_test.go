package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	passwordstorev1alpha1 "github.com/sorend/passwordstore-operator/api/v1alpha1"
	"github.com/sorend/passwordstore-operator/internal/gitstore"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
//
// They run the controllers in a manager against a real API server, so what is tested is what the
// operator does, including its watches and the schema of the CRDs. What this environment lacks
// is the controller manager of Kubernetes: there is no garbage collection, so Secrets are not
// deleted together with their owner.

const (
	// eventuallyTimeout is long enough for a reconcile that has to wait for the retry interval.
	eventuallyTimeout  = 30 * time.Second
	eventuallyInterval = 200 * time.Millisecond
)

var (
	ctx       context.Context
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())
	SetDefaultEventuallyTimeout(eventuallyTimeout)
	SetDefaultEventuallyPollingInterval(eventuallyInterval)

	var err error
	err = passwordstorev1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// The client of the tests reads from the API server, so that what a test reads is not
	// behind what the controllers have written.
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	By("starting the controllers")
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// The same as in main: Secrets are never cached.
		Client:     client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		Controller: ctrlconfig.Controller{SkipNameValidation: new(true)},
	})
	Expect(err).NotTo(HaveOccurred())

	options := Options{
		// The Git servers of the tests listen on the loopback interface, which the operator does not
		// connect to unless it is told to.
		Git: gitstore.NewManager(gitstore.Options{Timeout: 10 * time.Second, AllowInternalAddresses: true}),
		// A store does not check its repository again on its own during a test, so that what
		// a test sees was caused by what it did. A change of a store is seen through its
		// spec, and a Secret refreshes itself.
		StoreSyncInterval: time.Hour,
		RetryInterval:     time.Second,
		// Every refresh contacts the Git server, which is local.
		FetchCooldown:           0,
		MaxConcurrentReconciles: 4,
	}
	Expect((&PasswordStoreReconciler{
		Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Recorder: mgr.GetEventRecorder("passwordstore-controller"), Options: options,
	}).SetupWithManager(mgr)).To(Succeed())
	Expect((&ClusterPasswordStoreReconciler{
		Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Recorder: mgr.GetEventRecorder("clusterpasswordstore-controller"), Options: options,
	}).SetupWithManager(mgr)).To(Succeed())
	Expect((&PasswordStoreSecretReconciler{
		Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Scheme: mgr.GetScheme(),
		Recorder: mgr.GetEventRecorder("passwordstoresecret-controller"), Options: options,
	}).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
