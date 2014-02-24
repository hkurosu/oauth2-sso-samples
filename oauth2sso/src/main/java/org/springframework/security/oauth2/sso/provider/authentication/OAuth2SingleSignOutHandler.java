/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;

/**
 * @author Hiro
 *
 */
public class OAuth2SingleSignOutHandler implements LogoutHandler, InitializingBean {

	private String revokeTokenEndpointUri;

	private OAuth2ProtectedResourceDetails resource;

	private ClientTokenServices clientTokenServices;

	private String oauth2ClientContextConfig;

	public void setRevokeTokenEndpointUri(String revokeTokenEndpointUri) {
		this.revokeTokenEndpointUri = revokeTokenEndpointUri;
	}

	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	public void setClientTokenServices(ClientTokenServices clientTokenServices) {
		this.clientTokenServices = clientTokenServices;
	}

	public void setOauth2ClientContextConfig(String oauth2ClientContextConfig) {
		this.oauth2ClientContextConfig = oauth2ClientContextConfig;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(oauth2ClientContextConfig, "oauth2ClientContextConfig must be specified");
		Assert.notNull(revokeTokenEndpointUri, "revokeTokenEndpointUri must be specified");
		Assert.notNull(resource, "resource must be specified");
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		HttpSession httpSession = request.getSession(false);
		if (httpSession != null) {
			OAuth2ClientContext clientContext = (OAuth2ClientContext) request.getSession(false).getAttribute(
					oauth2ClientContextConfig);
			if (clientContext != null) {
				revokeTokenAtEndpoint(authentication.getName(), clientContext);
				httpSession.setAttribute(oauth2ClientContextConfig, null);
			}
		}

		// remove from token service
		if (clientTokenServices != null) {
			clientTokenServices.removeAccessToken(resource, authentication);
		}

	}

	protected void revokeTokenAtEndpoint(String username, OAuth2ClientContext clientContext) {
		// get authentication from authorization server
		try {
			OAuth2RestTemplate restClient = new OAuth2RestTemplate(resource, clientContext);
			restClient.delete(revokeTokenEndpointUri, username, clientContext.getAccessToken().getValue());
		}
		catch (RestClientException ignore) {
			// ignore this exception
		}
	}
}
