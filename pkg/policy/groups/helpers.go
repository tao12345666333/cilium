// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package groups

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cnpKindName = "derivative"
	parentCNP   = "io.cilium.network.policy.parent.uuid"
	cnpKindKey  = "io.cilium.network.policy.kind"
)

var (
	blockOwnerDeletionPtr = true
)

func getDerivativeName(cnp *cilium_v2.CiliumNetworkPolicy) string {
	return fmt.Sprintf(
		"%s-togroups-%s",
		cnp.GetObjectMeta().GetName(),
		cnp.GetObjectMeta().GetUID())
}

// createDerivativeCNP will return a new CNP based on the given rule.
// ccnpDerived argument indicates if the provided CNP is derived from CCNP or not.
// This is to make sure we call `Parse()` for the right construct so it don't fail.
func createDerivativeCNP(ctx context.Context, cnp *cilium_v2.CiliumNetworkPolicy, ccnpDerived bool) (*cilium_v2.CiliumNetworkPolicy, error) {
	// CNP informer may provide a CNP object without APIVersion or Kind.
	// Setting manually to make sure that the derivative policy works ok.
	derivativeCNP := &cilium_v2.CiliumNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      getDerivativeName(cnp),
			Namespace: cnp.ObjectMeta.Namespace,
			OwnerReferences: []v1.OwnerReference{{
				APIVersion:         cilium_v2.SchemeGroupVersion.String(),
				Kind:               cilium_v2.CNPKindDefinition,
				Name:               cnp.ObjectMeta.Name,
				UID:                cnp.ObjectMeta.UID,
				BlockOwnerDeletion: &blockOwnerDeletionPtr,
			}},
			Labels: map[string]string{
				parentCNP:  string(cnp.ObjectMeta.UID),
				cnpKindKey: cnpKindName,
			},
		},
	}

	var (
		rules api.Rules
		err   error
	)

	if ccnpDerived {
		// Temporary fix for CCNPs. See #12834.
		// TL;DR. CCNPs are converted into SlimCNPs and end up here so we need to
		// convert them back to CCNPs to allow proper parsing.
		// For more details on implementation see - https://github.com/cilium/cilium/pull/12851
		ccnp := &cilium_v2.CiliumClusterwideNetworkPolicy{
			TypeMeta:            cnp.TypeMeta,
			ObjectMeta:          cnp.ObjectMeta,
			CiliumNetworkPolicy: cnp,
			Status:              cnp.Status,
		}

		// Update the Kind of owner if the policy is CCNP derived.
		derivativeCNP.ObjectMeta.OwnerReferences[0].Kind = cilium_v2.CCNPKindDefinition
		rules, err = ccnp.Parse()
	} else {
		rules, err = cnp.Parse()
	}

	if err != nil {
		return derivativeCNP, fmt.Errorf("cannot parse policies: %v", err)
	}

	derivativeCNP.Specs = make(api.Rules, len(rules))
	for i, rule := range rules {
		if rule.RequiresDerivative() {
			derivativeCNP.Specs[i] = denyEgressRule()
		}
	}

	for i, rule := range rules {
		if !rule.RequiresDerivative() {
			derivativeCNP.Specs[i] = rule
			continue
		}
		newRule, err := rule.CreateDerivative(ctx)
		if err != nil {
			return derivativeCNP, err
		}
		derivativeCNP.Specs[i] = newRule
	}
	return derivativeCNP, nil
}

func denyEgressRule() *api.Rule {
	return &api.Rule{
		Egress: []api.EgressRule{},
	}
}

func updateOrCreateCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	k8sCNP, err := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}
		return k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Update(context.TODO(), k8sCNP, v1.UpdateOptions{})
	}
	return k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Create(context.TODO(), cnp, v1.CreateOptions{})
}

func updateOrCreateCCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumClusterwideNetworkPolicy, error) {
	k8sCCNP, err := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCCNP.Spec = cnp.Spec
		k8sCCNP.Specs = cnp.Specs
		k8sCCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}

		return k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().Update(context.TODO(), k8sCCNP, v1.UpdateOptions{})
	}

	return k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Create(context.TODO(), &cilium_v2.CiliumClusterwideNetworkPolicy{
			TypeMeta:            cnp.TypeMeta,
			ObjectMeta:          cnp.ObjectMeta,
			CiliumNetworkPolicy: cnp,
			Status:              cnp.Status,
		}, v1.CreateOptions{})
}

func updateDerivativeStatus(cnp *cilium_v2.CiliumNetworkPolicy, derivativeName string, err error, clusterScoped bool) error {
	status := cilium_v2.CiliumNetworkPolicyNodeStatus{
		LastUpdated: slimv1.Now(),
		Enforcing:   false,
	}

	if err != nil {
		status.OK = false
		status.Error = err.Error()
	} else {
		status.OK = true
	}

	if clusterScoped {
		return updateDerivativeCNPStatus(cnp, status, derivativeName)
	}

	return updateDerivativeCCNPStatus(cnp, status, derivativeName)
}

func updateDerivativeCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy, status cilium_v2.CiliumNetworkPolicyNodeStatus,
	derivativeName string) error {
	// This CNP can be modified by cilium agent or operator. To be able to push
	// the status correctly fetch the last version to avoid updates issues.
	k8sCNP, clientErr := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})

	if clientErr != nil {
		return fmt.Errorf("cannot get Kubernetes policy: %v", clientErr)
	}

	if k8sCNP.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care about that.
		groupsCNPCache.DeleteCNP(k8sCNP)
		return fmt.Errorf("policy UID mistmatch")
	}

	k8sCNP.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(k8sCNP)

	// TODO: Switch to JSON patch.
	_, err := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		UpdateStatus(context.TODO(), k8sCNP, v1.UpdateOptions{})

	return err
}

func updateDerivativeCCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy, status cilium_v2.CiliumNetworkPolicyNodeStatus,
	derivativeName string) error {
	k8sCCNP, clientErr := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})

	if clientErr != nil {
		return fmt.Errorf("cannot get Kubernetes policy: %v", clientErr)
	}

	if k8sCCNP.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care of that.
		groupsCNPCache.DeleteCNP(&cilium_v2.CiliumNetworkPolicy{
			ObjectMeta: k8sCCNP.ObjectMeta,
		})
		return fmt.Errorf("policy UID mistmatch")
	}

	k8sCCNP.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(&cilium_v2.CiliumNetworkPolicy{
		TypeMeta:   k8sCCNP.TypeMeta,
		ObjectMeta: k8sCCNP.ObjectMeta,
		Spec:       k8sCCNP.Spec,
		Specs:      k8sCCNP.Specs,
		Status:     k8sCCNP.Status,
	})

	// TODO: Switch to JSON patch
	_, err := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		UpdateStatus(context.TODO(), k8sCCNP, v1.UpdateOptions{})

	return err

}
