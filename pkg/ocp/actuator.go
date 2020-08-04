/*
Copyright 2019 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ocp

import (
	"context"
	"fmt"
	"errors"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kubernetesErrors "k8s.io/apimachinery/pkg/api/errors"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

type OCPActuator struct {
	Client client.Client
	Codec  *minterv1.ProviderCodec
}

const (
	DataSecretKey = "userData"
	KubevirtCredentialsSecretKey = "kubeconfig"
)
// NewActuator creates a new OCP actuator.
func NewActuator(client client.Client) (*OCPActuator, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		log.WithError(err).Error("error creating OCP codec")
		return nil, fmt.Errorf("error creating OCP codec: %v", err)
	}

	return &OCPActuator{
		Codec:  codec,
		Client: client,
	}, nil
}

// Exists checks if the credentials currently exist.
// TODO: in the future validate the expiration of the credentials
func (a *OCPActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")
	var err error

	existingSecret, err := a.getSecret(cr, logger)
	if err != nil {
		return false, err
	}

	return existingSecret != nil, nil
}

// Create the credentials.
func (a *OCPActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running create")
	return a.createSecret(ctx, cr, logger)
}

// Update the credentials to the provided definition.
func (a *OCPActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running update")

	existingSecret, err := a.getSecret(cr, logger)
	if err != nil {
		return err
	}

	if existingSecret == nil {
		return a.createSecret(ctx, cr, logger)
	}
	return nil
}


// Delete credentials
func (a *OCPActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running delete")


	existingSecret, err := a.getSecret(cr, logger)
	if err != nil {
		return err
	}
	if existingSecret != nil{
		logger.Debug("Deleting existing secret")
		err = a.Client.Delete(context.TODO(), existingSecret)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *OCPActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.KubevirtCloudCredSecretName}
}

func (a *OCPActuator) getSecret(cr *minterv1.CredentialsRequest, logger log.FieldLogger) (*corev1.Secret, error) {
	logger.Debug("running Exists")

	existingSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if kubernetesErrors.IsNotFound(err) {
			logger.Debug("target secret does not exist")
			return nil, nil
		}
		return nil, err
	}

	logger.Debug("target secret exists")
	return existingSecret, nil
}

func (a *OCPActuator) createSecret(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	// get the secret of the kubevirt credentials
	kubevirtCredentialsSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, a.GetCredentialsRootSecretLocation(), kubevirtCredentialsSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	// get the value from the secret
	infraClusterKubeconfig, ok := kubevirtCredentialsSecret.Data[KubevirtCredentialsSecretKey]
	if !ok {
		return errors.New("invalid mode")
	}

	// create a new secret in the tenant cluster
	sLog.Info("creating secret")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Spec.SecretRef.Namespace,
			Annotations: map[string]string{
				minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
			},
		},
		Data: map[string][]byte {
			DataSecretKey : infraClusterKubeconfig,
		},
	}

	err := a.Client.Create(context.TODO(), secret)
	if err != nil {
		sLog.WithError(err).Error("error creating secret")
		return err
	}
	sLog.Info("secret created successfully")
	return nil
}

func (a *OCPActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "OCP",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}
