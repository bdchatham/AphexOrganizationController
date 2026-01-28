package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/bdchatham/AphexControllerRuntime/api/v1alpha1"
	"github.com/bdchatham/AphexControllerRuntime/pkg/config"
	"github.com/bdchatham/AphexControllerRuntime/pkg/constants"
	"github.com/bdchatham/AphexControllerRuntime/pkg/helpers"
	"github.com/bdchatham/AphexControllerRuntime/pkg/metrics"
)

// OrganizationReconciler reconciles an Organization object
type OrganizationReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Log             logr.Logger
	Config          *config.Config
	statusHelper    *helpers.StatusHelper
	finalizerHelper *helpers.FinalizerHelper
}

// +kubebuilder:rbac:groups=aphex.io,resources=organizations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aphex.io,resources=organizations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aphex.io,resources=organizations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=triggers.tekton.dev,resources=eventlisteners,verbs=get;list;watch;create;update;patch

// Reconcile manages Organization resources
func (r *OrganizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) { //nolint:gocyclo
	logger := log.FromContext(ctx)

	metricsCollector := metrics.GetCollector()
	timer := metricsCollector.NewReconcileTimer(constants.ControllerNameOrganization)

	if err := r.ensureHelpers(logger); err != nil {
		logger.Error(err, "Failed to initialize helpers")
		timer.ObserveError(metrics.ClassifyError(err))
		return ctrl.Result{}, err
	}

	timeout := constants.DefaultProvisioningTimeout
	if r.Config != nil {
		timeout = r.Config.ProvisioningTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	org := &platformv1alpha1.Organization{}
	err := r.Get(ctx, req.NamespacedName, org)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		timer.ObserveError(metrics.ClassifyError(err))
		return ctrl.Result{}, err
	}

	if r.finalizerHelper.IsBeingDeleted(org) {
		result, err := r.handleDeletionWithHelper(ctx, logger, org)
		if err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
		} else {
			timer.ObserveSuccess()
			metrics.GetHealthState().RecordSuccess(constants.ControllerNameOrganization)
		}
		return result, err
	}

	if !r.finalizerHelper.HasFinalizer(org) {
		if err := r.validateOrganization(org); err != nil {
			logger.Error(err, "Validation failed, not adding finalizer")
			timer.ObserveError("validation")
			if patchErr := r.statusHelper.PatchStatus(ctx, org, map[string]interface{}{
				"phase":   constants.PhaseFailed,
				"message": fmt.Sprintf("Validation failed: %s", err.Error()),
			}); patchErr != nil {
				logger.Error(patchErr, "Failed to update status after validation failure")
			}
			return ctrl.Result{}, nil
		}
		if err := r.finalizerHelper.EnsureFinalizer(ctx, org); err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, err
		}
		timer.ObserveSuccess()
		return ctrl.Result{Requeue: true}, nil
	}

	if org.Spec.WebhookSecret == "" {
		secret, err := generateWebhookSecret()
		if err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, fmt.Errorf("failed to generate webhook secret: %w", err)
		}
		org.Spec.WebhookSecret = secret
		if err := r.Update(ctx, org); err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, err
		}
		timer.ObserveSuccess()
		return ctrl.Result{Requeue: true}, nil
	}

	if org.Status.Phase == "" {
		if err := r.statusHelper.PatchStatus(ctx, org, map[string]interface{}{
			"phase":      constants.PhasePending,
			"namespace":  fmt.Sprintf("org-%s", org.Name),
			"webhookURL": fmt.Sprintf("https://%s.%s", org.Name, constants.WebhookDomain),
			"message":    "Starting organization provisioning",
		}); err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, err
		}
		timer.ObserveSuccess()
		return ctrl.Result{Requeue: true}, nil
	}

	if org.Status.Phase == constants.PhasePending {
		if err := r.statusHelper.PatchStatus(ctx, org, map[string]interface{}{
			"phase":   constants.PhaseProvisioning,
			"message": "Provisioning organization resources",
		}); err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, err
		}
	}

	if err := r.provisionOrganization(ctx, org); err != nil {
		timer.ObserveError(metrics.ClassifyError(err))
		if patchErr := r.statusHelper.PatchStatus(ctx, org, map[string]interface{}{
			"phase":   constants.PhaseFailed,
			"message": err.Error(),
		}); patchErr != nil {
			logger.Error(patchErr, "Failed to update status after provisioning failure")
		}
		return ctrl.Result{}, err
	}

	if org.Status.Phase != constants.PhaseActive {
		if err := r.statusHelper.PatchStatus(ctx, org, map[string]interface{}{
			"phase":   constants.PhaseActive,
			"message": "Organization provisioned successfully",
		}); err != nil {
			timer.ObserveError(metrics.ClassifyError(err))
			return ctrl.Result{}, err
		}
	}

	timer.ObserveSuccess()
	metrics.GetHealthState().RecordSuccess(constants.ControllerNameOrganization)
	logger.V(1).Info("Organization reconciled successfully", "organization", org.Name)
	return ctrl.Result{}, nil
}

func (r *OrganizationReconciler) ensureHelpers(logger logr.Logger) error { //nolint:unparam
	if r.statusHelper == nil {
		retryCount := constants.DefaultStatusRetryCount
		if r.Config != nil {
			retryCount = r.Config.StatusRetryCount
		}
		r.statusHelper = helpers.NewStatusHelper(r.Client, logger, retryCount)
	}

	if r.finalizerHelper == nil {
		r.finalizerHelper = helpers.NewFinalizerHelper(r.Client, logger, constants.OrganizationFinalizer)
	}

	return nil
}

func (r *OrganizationReconciler) validateOrganization(org *platformv1alpha1.Organization) error {
	if org.Name == "" {
		return fmt.Errorf("organization name cannot be empty")
	}
	return nil
}

func (r *OrganizationReconciler) handleDeletionWithHelper(ctx context.Context, logger logr.Logger, org *platformv1alpha1.Organization) (ctrl.Result, error) { //nolint:unparam
	if !r.finalizerHelper.NeedsCleanup(org) {
		return ctrl.Result{}, nil
	}

	cleanupSteps := []helpers.CleanupStep{
		helpers.NewCleanupStep("Cloudflare tunnel", func(ctx context.Context) error {
			if err := r.deleteCloudflaredTunnel(ctx, org); err != nil {
				logger.Error(err, "Failed to delete Cloudflare tunnel, continuing with cleanup")
			}
			return nil
		}),
		helpers.NewCleanupStep("ClusterSecretStore", func(ctx context.Context) error {
			return r.cleanupClusterSecretStore(ctx, org)
		}),
		helpers.NewCleanupStep("ClusterRoleBinding", func(ctx context.Context) error {
			return r.cleanupClusterRoleBinding(ctx, org)
		}),
		helpers.NewCleanupStep("Organization namespace", func(ctx context.Context) error {
			return r.cleanupNamespace(ctx, org)
		}),
	}

	if err := r.finalizerHelper.HandleDeletionWithSteps(ctx, org, cleanupSteps); err != nil {
		return ctrl.Result{}, err
	}

	logger.V(1).Info("Organization deletion completed", "organization", org.Name)
	return ctrl.Result{}, nil
}

func (r *OrganizationReconciler) cleanupClusterSecretStore(ctx context.Context, org *platformv1alpha1.Organization) error {
	store := &esv1.ClusterSecretStore{}
	storeName := fmt.Sprintf("org-%s-store", org.Name)
	if err := r.Get(ctx, client.ObjectKey{Name: storeName}, store); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get ClusterSecretStore: %w", err)
	}
	if err := r.Delete(ctx, store); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete ClusterSecretStore: %w", err)
	}
	return nil
}

func (r *OrganizationReconciler) cleanupClusterRoleBinding(ctx context.Context, org *platformv1alpha1.Organization) error {
	crb := &rbacv1.ClusterRoleBinding{}
	crbName := fmt.Sprintf("eventlistener-%s", org.Name)
	if err := r.Get(ctx, client.ObjectKey{Name: crbName}, crb); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get ClusterRoleBinding: %w", err)
	}
	if err := r.Delete(ctx, crb); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete ClusterRoleBinding: %w", err)
	}
	return nil
}

func (r *OrganizationReconciler) cleanupNamespace(ctx context.Context, org *platformv1alpha1.Organization) error {
	namespace := &corev1.Namespace{}
	if err := r.Get(ctx, client.ObjectKey{Name: org.Status.Namespace}, namespace); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get organization namespace: %w", err)
	}
	if err := r.Delete(ctx, namespace); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete organization namespace: %w", err)
	}
	return nil
}

func (r *OrganizationReconciler) provisionOrganization(ctx context.Context, org *platformv1alpha1.Organization) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled before provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionNamespace(ctx, org); err != nil {
		return fmt.Errorf("failed to provision namespace: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled during provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionWebhookSecret(ctx, org); err != nil {
		return fmt.Errorf("failed to provision webhook secret: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled during provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionSecretStore(ctx, org); err != nil {
		return fmt.Errorf("failed to provision SecretStore: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled during provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionCloudflaredTunnel(ctx, org); err != nil {
		return fmt.Errorf("failed to provision Cloudflared tunnel: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled during provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionRBAC(ctx, org); err != nil {
		return fmt.Errorf("failed to provision RBAC: %w", err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled during provisioning: %w", ctx.Err())
	default:
	}

	if err := r.provisionEventListenerServiceAccount(ctx, org); err != nil {
		return fmt.Errorf("failed to provision EventListener ServiceAccount: %w", err)
	}

	return nil
}

func (r *OrganizationReconciler) provisionNamespace(ctx context.Context, org *platformv1alpha1.Organization) error {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: org.Status.Namespace,
			Labels: map[string]string{
				constants.LabelOrganization: org.Name,
				constants.LabelManagedBy:    constants.ManagedByOrganizationController,
				constants.LabelAphexOrg:     org.Name,
			},
		},
	}

	existingNs := &corev1.Namespace{}
	err := r.Get(ctx, client.ObjectKey{Name: org.Status.Namespace}, existingNs)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, namespace)
		}
		return err
	}

	existingNs.Labels = namespace.Labels
	return r.Update(ctx, existingNs)
}

func (r *OrganizationReconciler) provisionWebhookSecret(ctx context.Context, org *platformv1alpha1.Organization) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.WebhookSecretName,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		Data: map[string][]byte{
			"secret": []byte(org.Spec.WebhookSecret),
		},
	}

	existingSecret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: secret.Name, Namespace: secret.Namespace}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, secret)
		}
		return err
	}

	existingSecret.Data = secret.Data
	existingSecret.Labels = secret.Labels
	return r.Update(ctx, existingSecret)
}

const esoServiceAccountName = constants.ESOSecretsReaderAccount

func (r *OrganizationReconciler) provisionSecretStore(ctx context.Context, org *platformv1alpha1.Organization) error {
	if err := r.provisionESOServiceAccount(ctx, org); err != nil {
		return err
	}
	if err := r.provisionESORole(ctx, org); err != nil {
		return err
	}
	if err := r.provisionESORoleBinding(ctx, org); err != nil {
		return err
	}
	return r.provisionESOSecretStore(ctx, org)
}

func (r *OrganizationReconciler) provisionESOServiceAccount(ctx context.Context, org *platformv1alpha1.Organization) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      esoServiceAccountName,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
	}
	return r.createOrUpdateObject(ctx, sa)
}

func (r *OrganizationReconciler) provisionESORole(ctx context.Context, org *platformv1alpha1.Organization) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      esoServiceAccountName,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"org-secrets"},
			Verbs:         []string{"get"},
		}},
	}
	return r.createOrUpdateObject(ctx, role)
}

func (r *OrganizationReconciler) provisionESORoleBinding(ctx context.Context, org *platformv1alpha1.Organization) error {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      esoServiceAccountName,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     esoServiceAccountName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      esoServiceAccountName,
			Namespace: org.Status.Namespace,
		}},
	}
	return r.createOrUpdateObject(ctx, rb)
}

func (r *OrganizationReconciler) provisionESOSecretStore(ctx context.Context, org *platformv1alpha1.Organization) error {
	ns := org.Status.Namespace
	store := &esv1.ClusterSecretStore{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("org-%s-store", org.Name),
			Labels: map[string]string{
				constants.LabelOrganization: org.Name,
				constants.LabelManagedBy:    constants.ManagedByOrganizationController,
				constants.LabelOwnerName:    org.Name,
				constants.LabelOwnerKind:    "Organization",
			},
		},
		Spec: esv1.SecretStoreSpec{
			Conditions: []esv1.ClusterSecretStoreCondition{{
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						constants.LabelAphexOrg: org.Name,
					},
				},
			}},
			Provider: &esv1.SecretStoreProvider{
				Kubernetes: &esv1.KubernetesProvider{
					RemoteNamespace: ns,
					Server: esv1.KubernetesServer{
						CAProvider: &esv1.CAProvider{
							Type:      esv1.CAProviderTypeConfigMap,
							Name:      "kube-root-ca.crt",
							Key:       "ca.crt",
							Namespace: &ns,
						},
					},
					Auth: &esv1.KubernetesAuth{
						ServiceAccount: &esmeta.ServiceAccountSelector{
							Name:      esoServiceAccountName,
							Namespace: &ns,
						},
					},
				},
			},
		},
	}

	existing := &esv1.ClusterSecretStore{}
	err := r.Get(ctx, client.ObjectKey{Name: store.Name}, existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, store)
	}
	if err != nil {
		return err
	}
	store.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, store)
}

func (r *OrganizationReconciler) orgLabels(org *platformv1alpha1.Organization) map[string]string {
	return map[string]string{
		constants.LabelOrganization: org.Name,
		constants.LabelManagedBy:    constants.ManagedByOrganizationController,
	}
}

func (r *OrganizationReconciler) createOrUpdateObject(ctx context.Context, obj client.Object) error {
	existing, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("failed to deep copy object: type assertion failed")
	}
	err := r.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

func (r *OrganizationReconciler) provisionRBAC(ctx context.Context, org *platformv1alpha1.Organization) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.OrganizationAdminRoleName,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{"tekton.dev"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{"aphex.io"},
				Resources: []string{"repobindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch"},
			},
		},
	}

	existingRole := &rbacv1.Role{}
	err := r.Get(ctx, client.ObjectKey{Name: role.Name, Namespace: role.Namespace}, existingRole)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, role); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		existingRole.Rules = role.Rules
		existingRole.Labels = role.Labels
		if err := r.Update(ctx, existingRole); err != nil {
			return err
		}
	}

	for _, adminUser := range org.Spec.AdminUsers {
		roleBinding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%s", constants.OrganizationAdminRoleName, adminUser),
				Namespace: org.Status.Namespace,
				Labels:    r.orgLabels(org),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind: "User",
					Name: adminUser,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     constants.OrganizationAdminRoleName,
			},
		}

		existingRoleBinding := &rbacv1.RoleBinding{}
		err := r.Get(ctx, client.ObjectKey{Name: roleBinding.Name, Namespace: roleBinding.Namespace}, existingRoleBinding)
		if err != nil {
			if errors.IsNotFound(err) {
				if err := r.Create(ctx, roleBinding); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	return nil
}

func (r *OrganizationReconciler) provisionEventListenerServiceAccount(ctx context.Context, org *platformv1alpha1.Organization) error {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.EventListenerServiceAccount,
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
	}

	existingSA := &corev1.ServiceAccount{}
	err := r.Get(ctx, client.ObjectKey{Name: serviceAccount.Name, Namespace: serviceAccount.Namespace}, existingSA)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, serviceAccount); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", constants.EventListenerServiceAccount, org.Name),
			Labels: map[string]string{
				constants.LabelOrganization: org.Name,
				constants.LabelManagedBy:    constants.ManagedByOrganizationController,
				constants.LabelOwnerName:    org.Name,
				constants.LabelOwnerKind:    "Organization",
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      constants.EventListenerServiceAccount,
				Namespace: org.Status.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     constants.EventListenerAccessRole,
		},
	}

	existingClusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	err = r.Get(ctx, client.ObjectKey{Name: clusterRoleBinding.Name}, existingClusterRoleBinding)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, clusterRoleBinding); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func generateWebhookSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
