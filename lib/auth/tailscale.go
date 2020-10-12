package auth

import (
	"context"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"tailscale.com/net/interfaces"
)

type TailscaleAuthResponse struct {
	// Username is the name of authenticated user
	Username string `json:"username"`
	// Identity is the external identity
	Identity services.ExternalIdentity `json:"identity"`
	// Session is the created web session
	Session services.WebSession `json:"session,omitempty"`
	// Cert is the generated SSH client certificate
	Cert []byte `json:"cert,omitempty"`
	// TLSCert is PEM encoded TLS client certificate
	TLSCert []byte `json:"tls_cert,omitempty"`
	// Req is the original auth request
	Req services.TailscaleAuthRequest `json:"req"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy, used in console login
	HostSigners []services.CertAuthority `json:"host_signers"`
}

// AuthenticateTailscaleRequest checks that the request is coming from the tailscale network
func (s *AuthServer) AuthenticateTailscaleRequest(req services.TailscaleAuthRequest) (*TailscaleAuthResponse, error) {
	re, err := authenticateTailscaleRequest(req)
	event := &events.UserLogin{
		Metadata: events.Metadata{
			Type: events.UserLoginEvent,
		},
		Method: events.LoginMethodTailscale,
	}
	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		event.Status.Success = false
		event.Status.Error = err.Error()
		a.emitter.EmitAuditEvent(a.closeCtx, event)
		return nil, trace.Wrap(err)
	}
	event.Code = events.UserTailscaleLoginFailureCode
	event.Status.Success = true
	event.User = re.Username
	if err := a.emitter.EmitAuditEvent(a.closeCtx, event); err != nil {
		log.WithError(err).Warn("Failed to emit Tailscale login event.")
	}

	return re, nil
}

func (s *AuthServer) authenticateTailscaleRequest(req services.TailscaleAuthRequest) (*TailscaleAuthResponse, error) {
	logger := log.WithFields(logrus.Fields{trace.Component: "tailscale"})
	const errMsg = "no valid tailscale connection"
	if req.IP == "" {
		return nil, trace.BadParameter("Missing IP")
	}

	if !interfaces.IsTailscaleIP(req.IP) {
		log.Debugf("connecting IP is not a valid tailscale IP")
		return nil, trace.BadParameter(errMsg)
	}

	addr, _, err := interfaces.Tailscale()

	if err != nil {
		log.Debugf("Unable to collect interfaces on this host")
		return nil, trace.BadParameter(errMsg)
	}

	if addr == nil {
		log.Debugf("No tailscale device on this host, not possible to be connected via tailscale")
		return nil, trace.BadParamter(errMsg)
	}

	// Auth was successful, continue
	connector, err := s.Identity.GetTailscaleConnector(req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	params, err := s.calculateTailscaleUser(connector, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	user, err := s.createTailscaleUser(params)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	re := &TailscaleAuthResponse{
		Req: *req,
		Identity: services.ExternalIdentity{
			ConnectorID: params.connectorName,
			Username:    params.username,
		},
		Username: user.GetName(),
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := s.createWebSession(user, params.sessionTTL)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		re.auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.PublicKey) != 0 {
		sshCert, tlsCert, err := s.createSessionCert(user, params.sessionTTL, req.PublicKey, req.Compatibility, req.RouteToCluster, req.KubernetesCluster)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		clusterName, err := s.GetClusterName()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		re.auth.Cert = sshCert
		re.auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := s.GetCertAuthority(services.CertAuthID{
			Type:       services.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		re.auth.HostSigners = append(re.auth.HostSigners, authority)
	}

	return re, nil

}

// upsertTailscaleConnector creates or updates a Tailscale connector.
func (s *AuthServer) upsertTailscaleConnector(ctx context.Context, connector services.TailscaleConnector) error {
	if err := s.Identity.UpsertTailscaleConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	if err := s.emitter.EmitAuditEvent(s.closeCtx, &events.TailscaleConnectorCreate{
		Metadata: events.Metadata{
			Type: events.TailscaleConnectorCreatedEvent,
			Code: events.TailscaleConnectorCreatedCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: connector.GetName(),
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit Tailscale connector create event.")
	}

	return nil
}

// deleteTailscaleConnector deletes a Tailscale connector by name.
func (s *AuthServer) deleteTailscaleConnector(ctx context.Context, connectorName string) error {
	if err := s.Identity.DeleteTailscaleConnector(connectorName); err != nil {
		return trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &events.TailscaleConnectorDelete{
		Metadata: events.Metadata{
			Type: events.TailscaleConnectorDeletedEvent,
			Code: events.TailscaleConnectorDeletedCode,
		},
		UserMetadata: events.UserMetadata{
			User: clientUsername(ctx),
		},
		ResourceMetadata: events.ResourceMetadata{
			Name: connectorName,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit Tailscale connector delete event.")
	}

	return nil
}

func (s *AuthServer) calculateTailscaleUser(connector services.TailscaleConnector, ip string, request *services.TailscaleAuthRequest) (*createUserParams, error) {
	p := createUserParams{
		connectorName: connector.GetName(),
		username:      "Tailscale" + ip,
	}

	// Calculate logins, kubegroups, roles, and traits.
	p.logins, p.kubeGroups, p.kubeUsers = connector.MapClaims()
	if len(p.logins) == 0 {
		return nil, trace.BadParameter(
			"No logins configured for %q connector",
			connector.GetName())
	}
	p.roles = modules.GetModules().RolesFromLogins(p.logins)
	p.traits = modules.GetModules().TraitsFromLogins(p.username, p.logins, p.kubeGroups, p.kubeUsers)

	// Pick smaller for role: session TTL from role or requested TTL.
	roles, err := services.FetchRoles(p.roles, s.Access, p.traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(defaults.MaxCertDuration)
	p.sessionTTL = utils.MinTTL(roleTTL, request.CertTTL)

	return &p, nil
}

func (s *AuthServer) createTailscaleUser(p *createUserParams) (services.User, error) {

	log.WithFields(logrus.Fields{trace.Component: "tailscale"}).Debugf(
		"Generating dynamic identity %v/%v with logins: %v.",
		p.connectorName, p.ip)

	expires := s.GetClock().Now().UTC().Add(p.sessionTTL)

	user, err := services.GetUserMarshaler().GenerateUser(&services.UserV2{
		Kind:    services.KindUser,
		Version: services.V2,
		Metadata: services.Metadata{
			Name:      p.username,
			Namespace: defaults.Namespace,
			Expires:   &expires,
		},
		Spec: services.UserSpecV2{
			Roles:  p.roles,
			Traits: p.traits,
			TailscaleIdentities: []services.ExternalIdentity{{
				ConnectorID: p.connectorName,
				Username:    p.username,
			}},
			CreatedBy: services.CreatedBy{
				User: services.UserRef{Name: teleport.UserSystem},
				Time: s.GetClock().Now().UTC(),
				Connector: &services.ConnectorRef{
					Type:     teleport.ConnectorTailscale,
					ID:       p.connectorName,
					Identity: p.username,
				},
			},
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	existingUser, err := s.GetUser(p.username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	ctx := context.TODO()

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not a Tailscale user",
				existingUser.GetName())
		}

		if err := s.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if err := s.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}
