/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.sso.provider.authentication.OAuth2SingleSignOnFilter.OAuth2ClientContextAuthentication;
import org.springframework.util.Assert;

/**
 * @author hkurosu@gmail.com
 * @deprecated Custom implementation is no longer necessary. Use
 * {@link org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
 * OAuth2ClientAuthenticationProcessingFilter} and
 * {@link org.springframework.security.oauth2.provider.token.RemoteTokenServices RemoteTokenServices}.
 * @see org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
 * OAuth2ClientAuthenticationProcessingFilter
 * @see org.springframework.security.oauth2.provider.token.RemoteTokenServices RemoteTokenServices
 */
public class OAuth2SingleSignOnAuhtencationProvider implements AuthenticationProvider, InitializingBean {

	private ResourceServerTokenServices resourceServerTokenServices;

	public void setResourceServerTokenServices(ResourceServerTokenServices resourceServerTokenServices) {
		this.resourceServerTokenServices = resourceServerTokenServices;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(resourceServerTokenServices, "resourceServerTokenServices must be specieid");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		OAuth2ClientContext clientContext = ((OAuth2ClientContextAuthentication) authentication).getClientContext();
		OAuth2AccessToken accessToken = clientContext.getAccessToken();
		return resourceServerTokenServices.loadAuthentication(accessToken.getValue());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientContextAuthentication.class.isAssignableFrom(authentication);
	}
}
