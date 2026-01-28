package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	platformv1alpha1 "github.com/bdchatham/AphexControllerRuntime/api/v1alpha1"
	"github.com/bdchatham/AphexControllerRuntime/pkg/constants"
	triggersv1beta1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
)

func (r *OrganizationReconciler) provisionCloudflaredTunnel(ctx context.Context, org *platformv1alpha1.Organization) error { //nolint:gocyclo
	platformNS := constants.DefaultPlatformNamespace
	if r.Config != nil {
		platformNS = r.Config.PlatformNamespace
	}

	apiTokenSecret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: constants.CloudflareAPITokenSecret, Namespace: platformNS}, apiTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to get Cloudflare API token secret: %w", err)
	}

	apiToken := string(apiTokenSecret.Data["token"])
	if apiToken == "" {
		return fmt.Errorf("cloudflare API token not found in secret")
	}

	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		return fmt.Errorf("failed to create Cloudflare API client: %w", err)
	}

	accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
	if err != nil {
		return fmt.Errorf("failed to list Cloudflare accounts: %w", err)
	}
	if len(accounts) == 0 {
		return fmt.Errorf("no Cloudflare accounts found")
	}
	accountID := accounts[0].ID

	tunnelName := fmt.Sprintf("webhooks-%s", org.Name)
	existingCredentialsSecret := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKey{
		Name:      fmt.Sprintf("cloudflared-credentials-%s", org.Name),
		Namespace: org.Status.Namespace,
	}, existingCredentialsSecret)

	var tunnel cloudflare.Tunnel
	var tunnelSecret string

	if err == nil {
		credentialsJSON := existingCredentialsSecret.Data["credentials.json"]
		var credentials map[string]interface{}
		if json.Unmarshal(credentialsJSON, &credentials) == nil {
			if tunnelID, ok := credentials["TunnelID"].(string); ok && tunnelID != "" {
				if secret, ok := credentials["TunnelSecret"].(string); ok && secret != "" {
					tunnel = cloudflare.Tunnel{
						ID:     tunnelID,
						Name:   tunnelName,
						Secret: secret,
					}
					tunnelSecret = secret
				}
			}
		}
	}

	if tunnel.ID == "" {
		tunnel, err = r.createFreshTunnelWithSecret(ctx, api, accountID, tunnelName)
		if err != nil {
			return fmt.Errorf("failed to get or create Cloudflare tunnel: %w", err)
		}
		tunnelSecret = tunnel.Secret

		if err := r.createTunnelDNSRecord(ctx, api, accountID, org.Name, tunnel.ID); err != nil {
			return fmt.Errorf("failed to create DNS record: %w", err)
		}
	}

	credentials := map[string]interface{}{
		"AccountTag":   accountID,
		"TunnelSecret": tunnelSecret,
		"TunnelID":     tunnel.ID,
	}
	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal tunnel credentials: %w", err)
	}

	credentialsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cloudflared-credentials-%s", org.Name),
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		Data: map[string][]byte{
			"credentials.json": credentialsJSON,
		},
	}

	existingCredentialsSecret = &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKey{Name: credentialsSecret.Name, Namespace: credentialsSecret.Namespace}, existingCredentialsSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, credentialsSecret); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		existingCredentialsSecret.Data = credentialsSecret.Data
		existingCredentialsSecret.Labels = credentialsSecret.Labels
		if err := r.Update(ctx, existingCredentialsSecret); err != nil {
			return err
		}
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cloudflared-config",
			Namespace: org.Status.Namespace,
			Labels:    r.orgLabels(org),
		},
		Data: map[string]string{
			"config.yaml": fmt.Sprintf(`tunnel: %s
credentials-file: /etc/cloudflared/credentials/credentials.json

ingress:
  - hostname: %s.%s
    service: http://el-%s:8080
  - service: http_status:404`, tunnel.ID, org.Name, constants.WebhookDomain, constants.GitHubListenerName),
		},
	}

	existingConfigMap := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKey{Name: configMap.Name, Namespace: configMap.Namespace}, existingConfigMap)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, configMap); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		existingConfigMap.Data = configMap.Data
		existingConfigMap.Labels = configMap.Labels
		if err := r.Update(ctx, existingConfigMap); err != nil {
			return err
		}
	}

	deployment := r.buildCloudflaredDeployment(org)

	existingDeployment := &appsv1.Deployment{}
	err = r.Get(ctx, client.ObjectKey{Name: deployment.Name, Namespace: deployment.Namespace}, existingDeployment)
	if err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, deployment); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		existingDeployment.Spec = deployment.Spec
		existingDeployment.Labels = deployment.Labels
		if err := r.Update(ctx, existingDeployment); err != nil {
			return err
		}
	}

	if err := r.provisionEventListener(ctx, org); err != nil {
		return err
	}

	return r.provisionTriggerBinding(ctx, org)
}

func (r *OrganizationReconciler) buildCloudflaredDeployment(org *platformv1alpha1.Organization) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cloudflared-%s", org.Name),
			Namespace: org.Status.Namespace,
			Labels: map[string]string{
				constants.LabelOrganization: org.Name,
				constants.LabelManagedBy:    constants.ManagedByOrganizationController,
				"app":                       "cloudflared",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "cloudflared",
					"org": org.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "cloudflared",
						"org": org.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "cloudflared",
							Image: "cloudflare/cloudflared:latest",
							Args:  []string{"tunnel", "--config", "/etc/cloudflared/config/config.yaml", "run"},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/cloudflared/config",
									ReadOnly:  true,
								},
								{
									Name:      "credentials",
									MountPath: "/etc/cloudflared/credentials",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cloudflared-config",
									},
								},
							},
						},
						{
							Name: "credentials",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: fmt.Sprintf("cloudflared-credentials-%s", org.Name),
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *OrganizationReconciler) provisionEventListener(ctx context.Context, org *platformv1alpha1.Organization) error {
	orgNamespace := fmt.Sprintf("org-%s", org.Name)
	eventListener := &triggersv1beta1.EventListener{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.GitHubListenerName,
			Namespace: orgNamespace,
			Labels:    r.orgLabels(org),
		},
		Spec: triggersv1beta1.EventListenerSpec{
			ServiceAccountName: constants.EventListenerServiceAccount,
			NamespaceSelector: triggersv1beta1.NamespaceSelector{
				MatchNames: []string{},
			},
			TriggerGroups: []triggersv1beta1.EventListenerTriggerGroup{
				{
					Name: "github-webhooks",
					TriggerSelector: triggersv1beta1.EventListenerTriggerSelector{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								constants.LabelOrganization: org.Name,
							},
						},
					},
					Interceptors: []*triggersv1beta1.TriggerInterceptor{
						{
							Name: stringPtr("github"),
							Ref: triggersv1beta1.InterceptorRef{
								Name: "github",
								Kind: triggersv1beta1.ClusterInterceptorKind,
							},
						},
					},
				},
			},
		},
	}

	existingEventListener := &triggersv1beta1.EventListener{}
	err := r.Get(ctx, client.ObjectKey{Name: eventListener.Name, Namespace: eventListener.Namespace}, existingEventListener)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, eventListener)
		}
		return err
	}
	return nil
}

func (r *OrganizationReconciler) provisionTriggerBinding(ctx context.Context, org *platformv1alpha1.Organization) error {
	orgNamespace := fmt.Sprintf("org-%s", org.Name)
	triggerBinding := &triggersv1beta1.TriggerBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.GitHubPushBindingName,
			Namespace: orgNamespace,
			Labels:    r.orgLabels(org),
		},
		Spec: triggersv1beta1.TriggerBindingSpec{
			Params: []triggersv1beta1.Param{
				{
					Name:  "git-url",
					Value: "$(body.repository.clone_url)",
				},
				{
					Name:  "git-revision",
					Value: "$(body.after)",
				},
			},
		},
	}

	existingBinding := &triggersv1beta1.TriggerBinding{}
	err := r.Get(ctx, client.ObjectKey{Name: triggerBinding.Name, Namespace: triggerBinding.Namespace}, existingBinding)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, triggerBinding)
		}
		return err
	}
	return nil
}

func (r *OrganizationReconciler) createFreshTunnelWithSecret(ctx context.Context, api *cloudflare.API, accountID, tunnelName string) (cloudflare.Tunnel, error) {
	tunnels, _, err := api.ListTunnels(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelListParams{
		Name: tunnelName,
	})
	if err != nil {
		return cloudflare.Tunnel{}, fmt.Errorf("failed to list tunnels: %w", err)
	}

	for i := range tunnels {
		if tunnels[i].Name == tunnelName {
			err := api.DeleteTunnel(ctx, cloudflare.AccountIdentifier(accountID), tunnels[i].ID)
			if err != nil {
				return cloudflare.Tunnel{}, fmt.Errorf("failed to delete existing tunnel: %w", err)
			}
			break
		}
	}

	tunnelSecret := generateTunnelSecret()
	tunnel, err := api.CreateTunnel(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelCreateParams{
		Name:   tunnelName,
		Secret: tunnelSecret,
	})
	if err != nil {
		return cloudflare.Tunnel{}, fmt.Errorf("failed to create tunnel: %w", err)
	}

	tunnel.Secret = tunnelSecret
	return tunnel, nil
}

func generateTunnelSecret() string {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(secret)
}

func (r *OrganizationReconciler) deleteCloudflaredTunnel(ctx context.Context, org *platformv1alpha1.Organization) error {
	platformNS := constants.DefaultPlatformNamespace
	if r.Config != nil {
		platformNS = r.Config.PlatformNamespace
	}

	apiTokenSecret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: constants.CloudflareAPITokenSecret, Namespace: platformNS}, apiTokenSecret)
	if err != nil {
		return fmt.Errorf("failed to get Cloudflare API token secret: %w", err)
	}

	apiToken := string(apiTokenSecret.Data["token"])
	if apiToken == "" {
		return fmt.Errorf("cloudflare API token not found in secret")
	}

	credentialsSecret := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKey{
		Name:      fmt.Sprintf("cloudflared-credentials-%s", org.Name),
		Namespace: org.Status.Namespace,
	}, credentialsSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get tunnel credentials: %w", err)
	}

	credentialsJSON := credentialsSecret.Data["credentials.json"]
	var credentials map[string]interface{}
	if err := json.Unmarshal(credentialsJSON, &credentials); err != nil {
		return fmt.Errorf("failed to parse tunnel credentials: %w", err)
	}

	tunnelID, ok := credentials["TunnelID"].(string)
	if !ok {
		return fmt.Errorf("tunnel ID not found in credentials")
	}

	accountID, ok := credentials["AccountTag"].(string)
	if !ok {
		return fmt.Errorf("account ID not found in credentials")
	}

	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		return fmt.Errorf("failed to create Cloudflare API client: %w", err)
	}

	if err := r.deleteTunnelDNSRecord(ctx, api, accountID, org.Name); err != nil {
		return fmt.Errorf("failed to delete DNS record: %w", err)
	}

	err = api.CleanupTunnelConnections(ctx, cloudflare.AccountIdentifier(accountID), tunnelID)
	if err != nil {
		return fmt.Errorf("failed to cleanup tunnel connections for %s: %w", tunnelID, err)
	}

	err = api.DeleteTunnel(ctx, cloudflare.AccountIdentifier(accountID), tunnelID)
	if err != nil {
		return fmt.Errorf("failed to delete Cloudflare tunnel %s: %w", tunnelID, err)
	}

	return nil
}

func (r *OrganizationReconciler) deleteTunnelDNSRecord(ctx context.Context, api *cloudflare.API, _, orgName string) error {
	zones, err := api.ListZones(ctx, "arbiter-dev.com")
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}
	if len(zones) == 0 {
		return fmt.Errorf("zone arbiter-dev.com not found")
	}
	zoneID := zones[0].ID

	hostname := fmt.Sprintf("%s.arbiter-dev.com", orgName)

	records, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: hostname,
		Type: "CNAME",
	})
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	for i := range records {
		if err := api.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), records[i].ID); err != nil {
			return fmt.Errorf("failed to delete DNS record: %w", err)
		}
	}

	return nil
}

func (r *OrganizationReconciler) createTunnelDNSRecord(ctx context.Context, api *cloudflare.API, _, orgName, tunnelID string) error {
	zones, err := api.ListZones(ctx, "arbiter-dev.com")
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}
	if len(zones) == 0 {
		return fmt.Errorf("zone arbiter-dev.com not found")
	}
	zoneID := zones[0].ID

	hostname := fmt.Sprintf("%s.arbiter-dev.com", orgName)
	tunnelHostname := fmt.Sprintf("%s.cfargotunnel.com", tunnelID)

	_, err = api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
		Type:    "CNAME",
		Name:    hostname,
		Content: tunnelHostname,
		Proxied: cloudflare.BoolPtr(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %w", err)
	}

	return nil
}

func (r *OrganizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, &controller.Options{})
}

func (r *OrganizationReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts *controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&platformv1alpha1.Organization{}).
		WithOptions(*opts).
		Complete(r)
}

func int32Ptr(i int32) *int32 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}
