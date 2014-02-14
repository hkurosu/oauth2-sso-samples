/**
 * 
 */
package org.springframework.security.oauth.examples.keyhole;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * @author hirobumi.kurosu
 *
 */
public class OAuth2SingleSignOnFilter extends AbstractPreAuthenticatedProcessingFilter {
	private OAuth2ProtectedResourceDetails resource;
	private String userInfoUri;
	
	public OAuth2SingleSignOnFilter() {
		setAuthenticationManager(new DefaultFriendlyAuthenticationManager());
	}
	
	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}


	public void setUserInfoUri(String userInfoUrl) {
		this.userInfoUri = userInfoUrl;
	}

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource);
		AccessTokenRequest tokenRequest = restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
		tokenRequest.setCurrentUri(request.getRequestURL().toString());
		if (request.getParameter("code") != null) {
			tokenRequest.setAuthorizationCode(request.getParameter("code"));
		}
//		User user = restTemplate.getForObject(userInfoUri, User.class);
//		String user = restTemplate.getForObject(userInfoUri, String.class);
//		return user;
		PhotoServiceUser user = restTemplate.getForObject(userInfoUri, PhotoServiceUser.class);
		return new PreAuthenticatedAuthenticationToken(user.getUsername(), null, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return "N/A";
	}


	private static class DefaultFriendlyAuthenticationManager implements AuthenticationManager {
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			boolean authenticated = authentication.isAuthenticated();

			// If not already authenticated (the default) from the parent class
			if (authentication instanceof PreAuthenticatedAuthenticationToken && !authenticated) {

				PreAuthenticatedAuthenticationToken preAuth = (PreAuthenticatedAuthenticationToken) authentication;
				// Look inside the principal and see if that was marked as authenticated
				if (preAuth.getPrincipal() instanceof Authentication) {
					Authentication principal = (Authentication) preAuth.getPrincipal();
					preAuth = new PreAuthenticatedAuthenticationToken(principal, preAuth.getCredentials(), principal.getAuthorities());
					authenticated = principal.isAuthenticated();
				}
				preAuth.setAuthenticated(authenticated);

				authentication = preAuth;

			}

			return authentication;
		}
	}
	
}
