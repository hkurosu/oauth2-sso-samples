/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.authentication;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author hirobumi.kurosu
 *
 */
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler, InitializingBean {

	private URI logoutUri;

	private String targetUrlParameter = null;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	private final String logoutEndpointRedirectParameter = "redir";

	private String defaultLogoutSuccessUri = "/";

	public void setLogoutUri(URI logoutUri) {
		this.logoutUri = logoutUri;
	}

	public void setTargetUrlParameter(String targetUrlParameter) {
		this.targetUrlParameter = targetUrlParameter;
	}

	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	public void setDefaultLogoutSuccessUri(String defaultLogoutSuccessUri) {
		this.defaultLogoutSuccessUri = defaultLogoutSuccessUri;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(logoutUri, "logoutUri must be specified");
		Assert.notNull(redirectStrategy, "redirectStrategy must be specified");
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		String targetUrl = targetUrlParameter != null ? request.getParameter(targetUrlParameter) : null;
		if (targetUrl == null) {
			targetUrl = defaultLogoutSuccessUri;
		}
		if (!UrlUtils.isAbsoluteUrl(targetUrl)) {
			String[] temp = targetUrl.split("\\?");
			targetUrl = UrlUtils.buildFullRequestUrl(request.getScheme(), request.getServerName(),
					request.getServerPort(), temp[0], temp.length > 1 ? temp[1] : null);
		}

		UriComponentsBuilder logoutUriBuilder = UriComponentsBuilder.fromUri(logoutUri);
		logoutUriBuilder.replaceQueryParam(logoutEndpointRedirectParameter, targetUrl);
		String redirectUri = logoutUriBuilder.build().encode().toString();

		redirectStrategy.sendRedirect(request, response, redirectUri);
	}

}
