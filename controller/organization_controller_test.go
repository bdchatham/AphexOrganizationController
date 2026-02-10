package controller

import (
	"testing"

	platformv1alpha1 "github.com/bdchatham/AphexControllerRuntime/api/v1alpha1"
	"github.com/bdchatham/AphexControllerRuntime/pkg/constants"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"pgregory.net/rapid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)
	_ = platformv1alpha1.AddToScheme(scheme)
	return scheme
}

func newTestReconciler(objects ...client.Object) *OrganizationReconciler {
	scheme := testScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()
	return &OrganizationReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}
}

func organizationGenerator() *rapid.Generator[*platformv1alpha1.Organization] {
	return rapid.Custom(func(t *rapid.T) *platformv1alpha1.Organization {
		orgName := rapid.StringMatching(`[a-z][a-z0-9\-]{0,20}`).Draw(t, "orgName")
		orgNamespace := "org-" + orgName

		return &platformv1alpha1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Name:      orgName,
				Namespace: "default",
			},
			Spec: platformv1alpha1.OrganizationSpec{
				DisplayName: rapid.StringMatching(`[A-Za-z ]{3,30}`).Draw(t, "displayName"),
			},
			Status: platformv1alpha1.OrganizationStatus{
				Namespace: orgNamespace,
				Phase:     constants.PhaseProvisioning,
			},
		}
	})
}

// Feature: eventlistener-migration, Property 3: RoleBinding provisioning correctness
// **Validates: Requirements 2.1**
func TestProperty_RoleBindingProvisioningCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		org := organizationGenerator().Draw(t, "organization")
		reconciler := newTestReconciler()

		err := reconciler.provisionKBTriggerRoleBinding(t.Context(), org)
		if err != nil {
			t.Fatalf("provisionKBTriggerRoleBinding failed: %v", err)
		}

		roleBinding := &rbacv1.RoleBinding{}
		key := client.ObjectKey{
			Name:      "knowledgebase-trigger-manager",
			Namespace: org.Status.Namespace,
		}
		if err := reconciler.Get(t.Context(), key, roleBinding); err != nil {
			t.Fatalf("failed to get RoleBinding: %v", err)
		}

		if roleBinding.Name != "knowledgebase-trigger-manager" {
			t.Fatalf("expected RoleBinding name 'knowledgebase-trigger-manager', got %q", roleBinding.Name)
		}

		if roleBinding.Namespace != org.Status.Namespace {
			t.Fatalf("expected RoleBinding namespace %q, got %q", org.Status.Namespace, roleBinding.Namespace)
		}

		if roleBinding.RoleRef.Kind != "ClusterRole" {
			t.Fatalf("expected RoleRef kind 'ClusterRole', got %q", roleBinding.RoleRef.Kind)
		}

		if roleBinding.RoleRef.Name != "knowledgebase-trigger-manager" {
			t.Fatalf("expected RoleRef name 'knowledgebase-trigger-manager', got %q", roleBinding.RoleRef.Name)
		}

		if roleBinding.RoleRef.APIGroup != rbacv1.GroupName {
			t.Fatalf("expected RoleRef apiGroup %q, got %q", rbacv1.GroupName, roleBinding.RoleRef.APIGroup)
		}

		if len(roleBinding.Subjects) != 1 {
			t.Fatalf("expected exactly 1 subject, got %d", len(roleBinding.Subjects))
		}

		subject := roleBinding.Subjects[0]
		if subject.Kind != "ServiceAccount" {
			t.Fatalf("expected subject kind 'ServiceAccount', got %q", subject.Kind)
		}

		if subject.Name != "knowledgebase-controller" {
			t.Fatalf("expected subject name 'knowledgebase-controller', got %q", subject.Name)
		}

		if subject.Namespace != constants.DefaultPlatformNamespace {
			t.Fatalf("expected subject namespace %q, got %q", constants.DefaultPlatformNamespace, subject.Namespace)
		}

		if roleBinding.Labels[constants.LabelOrganization] != org.Name {
			t.Fatalf("expected label %s=%q, got %q",
				constants.LabelOrganization, org.Name, roleBinding.Labels[constants.LabelOrganization])
		}

		if roleBinding.Labels[constants.LabelManagedBy] != constants.ManagedByOrganizationController {
			t.Fatalf("expected label %s=%q, got %q",
				constants.LabelManagedBy, constants.ManagedByOrganizationController, roleBinding.Labels[constants.LabelManagedBy])
		}
	})
}

// Feature: eventlistener-migration, Property 4: RoleBinding cleanup on org deletion
// **Validates: Requirements 2.4**
func TestProperty_RoleBindingCleanupOnOrgDeletion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		org := organizationGenerator().Draw(t, "organization")

		existingRoleBinding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "knowledgebase-trigger-manager",
				Namespace: org.Status.Namespace,
				Labels: map[string]string{
					constants.LabelOrganization: org.Name,
					constants.LabelManagedBy:    constants.ManagedByOrganizationController,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "knowledgebase-trigger-manager",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "knowledgebase-controller",
				Namespace: constants.DefaultPlatformNamespace,
			}},
		}

		reconciler := newTestReconciler(existingRoleBinding)

		err := reconciler.cleanupKBTriggerRoleBinding(t.Context(), org)
		if err != nil {
			t.Fatalf("cleanupKBTriggerRoleBinding failed: %v", err)
		}

		roleBinding := &rbacv1.RoleBinding{}
		key := client.ObjectKey{
			Name:      "knowledgebase-trigger-manager",
			Namespace: org.Status.Namespace,
		}
		getErr := reconciler.Get(t.Context(), key, roleBinding)
		if getErr == nil {
			t.Fatal("expected RoleBinding to be absent after cleanup, but it still exists")
		}

		errCleanupAgain := reconciler.cleanupKBTriggerRoleBinding(t.Context(), org)
		if errCleanupAgain != nil {
			t.Fatalf("idempotent cleanup should not error, got: %v", errCleanupAgain)
		}
	})
}
