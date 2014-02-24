/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.token;

import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.ClientTokenServices;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author hirobumi.kurosu
 * 
 */
public class LocalClientTokenServices implements ClientTokenServices {

	protected final Log logger = LogFactory.getLog(getClass());

	private TokenStore tokenStore;

	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
		if (authentication instanceof OAuth2Authentication) {
			OAuth2AccessToken token = tokenStore.getAccessToken((OAuth2Authentication) authentication);
			if (token != null) {
				logger.debug("Found token for OAuth2Authentication");
				return token;
			}
		}
		Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(resource.getClientId());
		if (tokens == null || tokens.isEmpty()) {
			return null;
		}
		Iterator<OAuth2AccessToken> iter = tokens.iterator();
		while (iter.hasNext()) {
			OAuth2AccessToken token = iter.next();
			OAuth2Authentication oauth2Auth = tokenStore.readAuthentication(token);
			if (oauth2Auth != null && resource.getClientId().equals(oauth2Auth.getOAuth2Request().getClientId())
					&& oauth2Auth.getName().equals(authentication.getName())) {
				logger.debug("token for user: " + authentication.getName() + " found");
				return token;
			}
		}
		logger.debug("token not found");
		return null;
	}

	@Override
	public void saveAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication,
			OAuth2AccessToken accessToken) {
		OAuth2Authentication oauth2Auth = null;
		if (authentication instanceof OAuth2Authentication) {
			oauth2Auth = (OAuth2Authentication) authentication;
			logger.debug("authentication is a OAuth2Authentication");
		}
		else {
			oauth2Auth = tokenStore.readAuthentication(accessToken);
			logger.debug("Found OAuth2 authentication in the store");
		}
		if (oauth2Auth == null) {
			// TODO: probably, we should create OAuth2Authentication from Authentication somehow?
			logger.debug("token is not stored as auth is not OAuth2Authentication");
		}
		else {
			tokenStore.storeAccessToken(accessToken, oauth2Auth);
		}
	}

	@Override
	public void removeAccessToken(OAuth2ProtectedResourceDetails resource, Authentication authentication) {
		if (authentication instanceof OAuth2Authentication) {
			OAuth2AccessToken token = tokenStore.getAccessToken((OAuth2Authentication) authentication);
			if (token != null) {
				logger.debug("Found token for OAuth2Authentication");
				tokenStore.removeAccessToken(token);
			}
		}
	}

}
