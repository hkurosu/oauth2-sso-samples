/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

/**
 * @author hirobumi.kurosu
 * 
 */
public class OAuth2SingleSignOnFilter extends AbstractAuthenticationProcessingFilter {

	private String oauth2ClientContextConfig;


	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(oauth2ClientContextConfig, "oauth2ClientContextConfig must be specified");
	}

	public OAuth2SingleSignOnFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		OAuth2ClientContext clientContext = prepareClientContext(request);
		Authentication authentication = new OAuth2ClientContextAuthentication(clientContext);
		return getAuthenticationManager().authenticate(authentication);
	}

	protected OAuth2ClientContext prepareClientContext(HttpServletRequest request) {
		HttpSession httpSession = request.getSession(true); // ensure HttpSession
		// lookup saved clientContext
		OAuth2ClientContext clientContext = (OAuth2ClientContext) httpSession.getAttribute(oauth2ClientContextConfig);
		if (clientContext == null) { // not yet, saved
			AccessTokenRequest tokenRequest = new DefaultAccessTokenRequest(request.getParameterMap());
			// tokenRequest.setCurrentUri(request.getRequestURL().toString());
			tokenRequest.setCurrentUri((String) request.getAttribute("currentUri"));
			clientContext = new DefaultOAuth2ClientContext(tokenRequest);
			httpSession.setAttribute("oauth2ClientContext", clientContext);
		}
		else { // refresh code
			String code = request.getParameter("code");
			clientContext.getAccessTokenRequest().set("code", code);
		}

		return clientContext;
	}

	/**
	 * @return the oauth2ClientContextConfig
	 */
	public String getOauth2ClientContextConfig() {
		return oauth2ClientContextConfig;
	}

	/**
	 * @param oauth2ClientContextConfig the oauth2ClientContextConfig to set
	 */
	public void setOauth2ClientContextConfig(String oauth2ClientContextConfig) {
		this.oauth2ClientContextConfig = oauth2ClientContextConfig;
	}

	@SuppressWarnings("serial")
	class OAuth2ClientContextAuthentication extends PreAuthenticatedAuthenticationToken {
		OAuth2ClientContextAuthentication(OAuth2ClientContext clientContext) {
			super(clientContext, null);
		}

		OAuth2ClientContext getClientContext() {
			return (OAuth2ClientContext) getPrincipal();
		}
	}
}
