/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * @author hirobumi.kurosu
 * 
 */
public class OAuth2SingleSignOnFilter extends AbstractPreAuthenticatedProcessingFilter {

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		HttpSession httpSession = request.getSession(true); // ensure HttpSession
		OAuth2ClientContext clientContext = (OAuth2ClientContext) httpSession.getAttribute("oauth2ClientContext");

		AccessTokenRequest tokenRequest = null;
		if (clientContext == null) {
			tokenRequest = new DefaultAccessTokenRequest(request.getParameterMap());
			// tokenRequest.setCurrentUri(request.getRequestURL().toString());
			tokenRequest.setCurrentUri((String) request.getAttribute("currentUri"));
			clientContext = new DefaultOAuth2ClientContext(tokenRequest);
			httpSession.setAttribute("oauth2ClientContext", clientContext);
		}
		else {
			String code = request.getParameter("code");
			clientContext.getAccessTokenRequest().set("code", code);
		}

		return clientContext;
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return "N/A";
	}
}
