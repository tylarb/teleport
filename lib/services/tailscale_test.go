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
	"github.com/gravitational/teleport/lib/utils"

	check "gopkg.in/check.v1"
)

type TailscaleSuite struct{}

var _ = check.Suite(&TailscaleSuite{})

func (s *TailscaleSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
}

func (s *TailscaleSuite) TestUnmarshal(c *check.C) {
	data := []byte(`{"kind": "tailscale",
"version": "v1",
"metadata": {
  "name": "tailscale"
},
"spec": {
  "display": "Tailscale",
  "allow": [{
    "logins": ["admin"]
  }]
}}`)
	connector, err := GetTailscaleConnectorMarshaler().Unmarshal(data)
	c.Assert(err, check.IsNil)
	expected := NewTailscaleConnector("tailscale", TailscaleConnectorSpecV1{
		Display: "Tailscale",
		Logins: []LoginMapping{
			{
				Logins: []string{"admin"},
			},
		},
	})
	c.Assert(expected, check.DeepEquals, connector)
}

func (s *TailscaleSuite) TestMapClaims(c *check.C) {
	connector := NewTailscaleConnector("tailscale", TailscaleConnectorSpecV1{
		Display: "Tailscale",
		Logins: []LoginMapping{
			{
				Logins:     []string{"admin", "dev"},
				KubeGroups: []string{"system:masters", "kube-devs"},
				KubeUsers:  []string{"alice@example.com"},
			},
			{
				Logins:     []string{"dev", "test"},
				KubeGroups: []string{"kube-devs"},
			},
		},
	})
	logins, kubeGroups, kubeUsers := connector.MapClaims()

	c.Assert(logins, check.DeepEquals, []string{"admin", "dev", "test"})
	c.Assert(kubeGroups, check.DeepEquals, []string{"system:masters", "kube-devs"})
	c.Assert(kubeUsers, check.DeepEquals, []string{"alice@example.com"})

}
