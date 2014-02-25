/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;

/**
 * @author Hiro
 *
 */
public class OAuth2SingleSignOutHandler implements LogoutHandler, InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

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
		// revoke acccess token at authorization endpoint
		if (authentication instanceof OAuth2Authentication) {
			revokeTokenAtAuthenticationEndpoint((OAuth2Authentication) authentication);
		}

		// clear clientContext in HtpSession
		HttpSession httpSession = request.getSession(false);
		if (httpSession != null) {
			if (logger.isDebugEnabled()) {
				if (httpSession.getAttribute(oauth2ClientContextConfig) != null) {
					logger.debug("Remove session attribibute: " + oauth2ClientContextConfig);
				}
			}
			httpSession.removeAttribute(oauth2ClientContextConfig);
		}

		// remove from token service
		if (clientTokenServices != null) {
			if (logger.isDebugEnabled()) {
				if (clientTokenServices.getAccessToken(resource, authentication) != null) {
					logger.debug("Remove access token from tokenStore");
				}
			}
			clientTokenServices.removeAccessToken(resource, authentication);
		}
	}

	protected void revokeTokenAtAuthenticationEndpoint(OAuth2Authentication authentication) {
		String username = authentication.getName();
		if (username == null) {
			logger.debug("unknown username");
			return;
		}
		OAuth2AccessToken accessToken = clientTokenServices.getAccessToken(resource, authentication);
		if (accessToken == null) {
			logger.debug("Access token not found.");
			return;
		}

		// get authentication from authorization server
		try {
			OAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(accessToken);
			OAuth2RestTemplate restClient = new OAuth2RestTemplate(resource, clientContext);
			restClient.delete(revokeTokenEndpointUri, username, accessToken.getValue());
			logger.debug("Successfully revoked Access token at authorization endpoint");
		}
		catch (RestClientException ignore) {
			// ignore this exception
			logger.warn("Error in REST call: " + ignore.getMessage());
		}
	}
}
