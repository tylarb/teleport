/*
Copyright 2017 Gravitational, Inc.

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

package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// TailscaleConnector defines an interface for a Tailscale connector
type TailscaleConnector interface {
	// ResourceWithSecrets is a common interface for all resources
	ResourceWithSecrets
	// CheckAndSetDefaults validates the connector and sets some defaults
	CheckAndSetDefaults() error
	// GetLogins returns the mapping of Tailscale ips to allowed logins
	GetLogins() []LoginMapping
	// SetLogins sets the mapping of Tailscale ips to allowed logins
	SetLogins([]LoginMapping)
	// MapClaims returns the list of allowed logins based on retrieved claims
	// returns list of logins and kubernetes groups
	MapClaims() (logins []string, kubeGroups []string, kubeUsers []string)
	// GetDisplay returns the connector display name
	GetDisplay() string
	// SetDisplay sets the connector display name
	SetDisplay(string)
}

// NewTailscaleConnector creates a new Tailscale connector from name and spec
func NewTailscaleConnector(name string, spec TailscaleConnectorSpecV1) TailscaleConnector {
	return &TailscaleConnectorV1{
		Kind:    KindTailscaleConnector,
		Version: V1,
		Metadata: Metadata{
			Name:      name,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}
}

// TailscaleConnectorV1 represents a Tailscale connector
type TailscaleConnectorV1 struct {
	// Kind is a resource kind, for Tailscale connector it is "tailscale"
	Kind string `json:"kind"`
	// SubKind is a resource sub kind
	SubKind string `json:"sub_kind,omitempty"`
	// Version is resource version
	Version string `json:"version"`
	// Metadata is resource metadata
	Metadata Metadata `json:"metadata"`
	// Spec contains connector specification
	Spec TailscaleConnectorSpecV1 `json:"spec"`
}

// TailscaleConnectorSpecV1 is the current Tailscale connector spec
type TailscaleConnectorSpecV1 struct {
	// Logins maps Tailscale ip memberships onto allowed logins/roles
	Logins []LoginMapping `json:"allow"`
	// Display is the connector display name
	Display string `json:"display"`
}

// LoginMapping represents a membership mapping
type LoginMapping struct {
	// Logins is a list of allowed logins for this ip
	Logins []string `json:"logins,omitempty"`
	// KubeGroups is a list of allowed kubernetes groups for this ip
	KubeGroups []string `json:"kubernetes_groups,omitempty"`
	// KubeUsers is a list of allowed kubernetes users to impersonate for
	// this ip
	KubeUsers []string `json:"kubernetes_users,omitempty"`
}

// GetVersion returns resource version
func (c *TailscaleConnectorV1) GetVersion() string {
	return c.Version
}

// GetKind returns resource kind
func (c *TailscaleConnectorV1) GetKind() string {
	return c.Kind
}

// GetSubKind returns resource sub kind
func (c *TailscaleConnectorV1) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind
func (c *TailscaleConnectorV1) SetSubKind(s string) {
	c.SubKind = s
}

// GetResourceID returns resource ID
func (c *TailscaleConnectorV1) GetResourceID() int64 {
	return c.Metadata.ID
}

// SetResourceID sets resource ID
func (c *TailscaleConnectorV1) SetResourceID(id int64) {
	c.Metadata.ID = id
}

// GetName returns the name of the connector
func (c *TailscaleConnectorV1) GetName() string {
	return c.Metadata.GetName()
}

// SetName sets the connector name
func (c *TailscaleConnectorV1) SetName(name string) {
	c.Metadata.SetName(name)
}

// Expires returns the connector expiration time
func (c *TailscaleConnectorV1) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// SetExpiry sets the connector expiration time
func (c *TailscaleConnectorV1) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// SetTTL sets the connector TTL
func (c *TailscaleConnectorV1) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	c.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns the connector metadata
func (c *TailscaleConnectorV1) GetMetadata() Metadata {
	return c.Metadata
}

// WithoutSecrets returns an instance of resource without secrets
func (c *TailscaleConnectorV1) WithoutSecrets() Resource {
	return c
}

// CheckAndSetDefaults verifies the connector is valid and sets some defaults
func (c *TailscaleConnectorV1) CheckAndSetDefaults() error {
	if err := c.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetLogins returns the connector ip mappings
func (c *TailscaleConnectorV1) GetLogins() []LoginMapping {
	return c.Spec.Logins
}

// SetLogins sets the connector ip membership mappings
func (c *TailscaleConnectorV1) SetLogins(logins []LoginMapping) {
	c.Spec.Logins = logins
}

// GetDisplay returns the connector display name
func (c *TailscaleConnectorV1) GetDisplay() string {
	return c.Spec.Display
}

// SetDisplay sets the connector display name
func (c *TailscaleConnectorV1) SetDisplay(display string) {
	c.Spec.Display = display
}

// MapClaims returns a list of logins based on the provided claims,
// returns a list of logins and list of kubernetes groups
func (c *TailscaleConnectorV1) MapClaims() ([]string, []string, []string) {
	var logins, kubeGroups, kubeUsers []string
	for _, Logins := range c.GetLogins() {
		logins = append(logins, Logins.Logins...)
		kubeGroups = append(kubeGroups, Logins.KubeGroups...)
		kubeUsers = append(kubeUsers, Logins.KubeUsers...)

	}
	return utils.Deduplicate(logins), utils.Deduplicate(kubeGroups), utils.Deduplicate(kubeUsers)
}

var tailscaleConnectorMarshaler TailscaleConnectorMarshaler = &TeleportTailscaleConnectorMarshaler{}

// SetTailscaleConnectorMarshaler sets Tailscale connector marshaler
func SetTailscaleConnectorMarshaler(m TailscaleConnectorMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	tailscaleConnectorMarshaler = m
}

// GetTailscaleConnectorMarshaler returns currently set Tailscale connector marshaler
func GetTailscaleConnectorMarshaler() TailscaleConnectorMarshaler {
	marshalerMutex.RLock()
	defer marshalerMutex.RUnlock()
	return tailscaleConnectorMarshaler
}

// TailscaleConnectorMarshaler defines interface for Tailscale connector marshaler
type TailscaleConnectorMarshaler interface {
	// Unmarshal unmarshals connector from binary representation
	Unmarshal(bytes []byte) (TailscaleConnector, error)
	// Marshal marshals connector to binary representation
	Marshal(c TailscaleConnector, opts ...MarshalOption) ([]byte, error)
}

// GetTailscaleConnectorSchema returns schema for Tailscale connector
func GetTailscaleConnectorSchema() string {
	return fmt.Sprintf(TailscaleConnectorV1SchemaTemplate, MetadataSchema, TailscaleConnectorSpecV1Schema)
}

// TeleportTailscaleConnectorMarshaler is the default Tailscale connector marshaler
type TeleportTailscaleConnectorMarshaler struct{}

// UnmarshalTailscaleConnector unmarshals Tailscale connector from JSON
func (*TeleportTailscaleConnectorMarshaler) Unmarshal(bytes []byte) (TailscaleConnector, error) {
	var h ResourceHeader
	if err := json.Unmarshal(bytes, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case V1:
		var c TailscaleConnectorV1
		if err := utils.UnmarshalWithSchema(GetTailscaleConnectorSchema(), &c, bytes); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := c.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		return &c, nil
	}
	return nil, trace.BadParameter(
		"Tailscale connector resource version %q is not supported", h.Version)
}

// MarshalTailscaleConnector marshals Tailscale connector to JSON
func (*TeleportTailscaleConnectorMarshaler) Marshal(c TailscaleConnector, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch resource := c.(type) {
	case *TailscaleConnectorV1:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *resource
			copy.SetResourceID(0)
			resource = &copy
		}
		return utils.FastMarshal(resource)
	default:
		return nil, trace.BadParameter("unrecognized resource version %T", c)
	}
}

// TailscaleConnectorV1SchemaTemplate is the JSON schema for a Tailscale connector
const TailscaleConnectorV1SchemaTemplate = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "spec", "metadata", "version"],
  "properties": {
    "kind": {"type": "string"},
    "version": {"type": "string", "default": "v1"},
    "metadata": %v,
    "spec": %v
  }
}`

// TailscaleConnectorSpecV1Schema is the JSON schema for Tailscale connector spec
var TailscaleConnectorSpecV1Schema = fmt.Sprintf(`{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "display": {"type": "string"},
    "allow": {
      "type": "array",
      "items": %v
    }
  }
}`, LoginMappingSchema)

var LoginMappingSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "logins": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "kubernetes_groups": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "kubernetes_users": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  }
}`
