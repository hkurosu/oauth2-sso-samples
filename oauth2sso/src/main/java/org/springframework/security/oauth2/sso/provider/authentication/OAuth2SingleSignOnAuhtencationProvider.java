/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

/**
 * @author hkurosu@gmail.com
 *
 */
public class OAuth2SingleSignOnAuhtencationProvider implements AuthenticationProvider, InitializingBean {
	private String userInfoUri;

	private JwtTokenServices jwtTokenConverter;

	private OAuth2ProtectedResourceDetails resource;

	private ClientTokenServices clientTokenServices;

	public void setUserInfoUri(String userInfoUrl) {
		this.userInfoUri = userInfoUrl;
	}

	public void setJwtTokenConverter(JwtTokenServices jwtTokenServices) {
		this.jwtTokenConverter = jwtTokenServices;
	}

	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	public void setClientTokenServices(ClientTokenServices clientTokenServices) {
		this.clientTokenServices = clientTokenServices;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(userInfoUri, "userInfoUri must be specified");
		Assert.notNull(resource, "resource must be specified");
		Assert.notNull(jwtTokenConverter, "jwtTokenConverter must be specified");
		Assert.notNull(clientTokenServices, "clientTokenServices must be specieid");;
	}

	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		if (!(authentication.getPrincipal() instanceof OAuth2ClientContext)) {
			return null;
		}
		OAuth2ClientContext clientContext = (OAuth2ClientContext) authentication.getPrincipal();
		OAuth2RestTemplate restClient = new OAuth2RestTemplate(resource, clientContext);
		
		// get authentication from authorization server
		String jwtToken = restClient.getForObject(userInfoUri, String.class);
		OAuth2Authentication oauth2Auth = jwtTokenConverter.loadAuthentication(jwtToken);

		// save the token to the token store.
		if (clientTokenServices != null) {
			clientTokenServices.saveAccessToken(resource, oauth2Auth, restClient.getAccessToken());
		}

		return oauth2Auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
