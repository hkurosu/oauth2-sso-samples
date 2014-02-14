/**
 * 
 */
package org.springframework.security.oauth.examples.keyhole.filter;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * @author hirobumi.kurosu
 * 
 */
public class OAuth2SingleSignOnFilter extends AbstractPreAuthenticatedProcessingFilter {
	private OAuth2ProtectedResourceDetails resource;

	private String userInfoUri;

	private JwtTokenServices jwtTokenConverter;

	private OAuth2RestOperations restTemplate;

	private ClientTokenServices clientTokenServices;

	public OAuth2SingleSignOnFilter() {
		setAuthenticationManager(new DefaultFriendlyAuthenticationManager());
	}

	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	public void setUserInfoUri(String userInfoUrl) {
		this.userInfoUri = userInfoUrl;
	}

	public void setJwtTokenConverter(JwtTokenServices jwtTokenServices) {
		this.jwtTokenConverter = jwtTokenServices;
	}

	public void setRestTemplate(OAuth2RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public void setClientTokenServices(ClientTokenServices clientTokenServices) {
		this.clientTokenServices = clientTokenServices;
	}

	private OAuth2RestOperations getRestTemplate(HttpServletRequest request) {
		// TODO: work-around of error shown below. Ideally, restTemplate should be configured as <oauth:rest-template/>
		// in bean definitions. How / When is the session established?
		//
		// <error message>
		// HTTP Status 500 - Error creating bean with name
		// 'scopedTarget.org.springframework.security.oauth2.client.DefaultOAuth2ClientContext#0': Scope 'session' is
		// not active for the current thread; consider defining a scoped proxy for this bean if you intend to refer to
		// it from a singleton; nested exception is java.lang.IllegalStateException: No thread-bound request found: Are
		// you referring to request attributes outside of an actual web request, or processing a request outside of the
		// originally receiving thread? If you are actually operating within a web request and still receive this
		// message, your code is probably running outside of DispatcherServlet/DispatcherPortlet: In this case, use
		// RequestContextListener or RequestContextFilter to expose the current request.
		// </error message>
		OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource == null ? this.restTemplate.getResource()
				: resource);
		// AccessTokenProviderChain accessTokenProvider = new AccessTokenProviderChain(
		// Arrays.<AccessTokenProvider> asList(new AuthorizationCodeAccessTokenProvider(),
		// new ImplicitAccessTokenProvider(), new ResourceOwnerPasswordAccessTokenProvider(),
		// new ClientCredentialsAccessTokenProvider()));
		// accessTokenProvider.setClientTokenServices(clientTokenServices);
		// restTemplate.setAccessTokenProvider(accessTokenProvider);

		AccessTokenRequest tokenRequest = restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
		tokenRequest.setCurrentUri(request.getRequestURL().toString());
		if (request.getParameter("code") != null) {
			tokenRequest.setAuthorizationCode(request.getParameter("code"));
		}

		return restTemplate;
	}

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		OAuth2RestOperations restClient = getRestTemplate(request);
		// get authentication from authorization server
		String jwtToken = restClient.getForObject(userInfoUri, String.class);
		OAuth2Authentication authentication = jwtTokenConverter.loadAuthentication(jwtToken);

		//
		clientTokenServices.saveAccessToken(resource, authentication, restClient.getAccessToken());

		// work-around: JWT does not carry the principal as User, but as String.
		// sparklr apps needs to have User principals to verify the grant
		Authentication userAuth = authentication.getUserAuthentication();
		User user = new User(userAuth.getName(), "", userAuth.getAuthorities()); // needs password != null
		return user;
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return "N/A";
	}

	private static class DefaultFriendlyAuthenticationManager implements AuthenticationManager {
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			// make sure authorities are populated to authentication
			User user = (User) authentication.getPrincipal();
			PreAuthenticatedAuthenticationToken auth = new PreAuthenticatedAuthenticationToken(
					authentication.getPrincipal(), authentication.getCredentials(), user.getAuthorities());
			auth.setAuthenticated(true);
			return auth;
		}
	}
}
