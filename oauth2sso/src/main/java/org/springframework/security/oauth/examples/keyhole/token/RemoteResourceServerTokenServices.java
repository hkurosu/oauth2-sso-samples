/**
 * 
 */
package org.springframework.security.oauth.examples.keyhole.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author hirobumi.kurosu
 * 
 */
public class RemoteResourceServerTokenServices implements ResourceServerTokenServices {
	private OAuth2ProtectedResourceDetails resource;

	private String userInfoUri;

	private JwtTokenServices jwtTokenServices;

	private TokenStore tokenStore;

	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	public void setUserInfoUri(String userInfoUrl) {
		this.userInfoUri = userInfoUrl;
	}

	public void setJwtTokenServices(JwtTokenServices jwtTokenServices) {
		this.jwtTokenServices = jwtTokenServices;
	}

	public void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
		OAuth2AccessToken token = readAccessToken(accessToken);
		if (token == null) {
			throw new InvalidTokenException("Invalid access token: " + token);
		}
		return tokenStore.readAuthentication(token);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		OAuth2AccessToken token = tokenStore.readAccessToken(accessToken);
		if (token != null && !token.isExpired()) {
			return token;
		}

		OAuth2Authentication auth = null;
		try {
			token = new DefaultOAuth2AccessToken(accessToken);
			auth = accuireAuthentication(token);
		}
		catch (UserRedirectRequiredException e) {
		}
		if (auth == null) {
			throw new InvalidTokenException("Invalid access token: " + accessToken);
		}
		// else if (token.isExpired()) {
		// tokenStore.removeAccessToken(token);
		// throw new InvalidTokenException("Access token expired: " + token);
		// }

		tokenStore.storeAccessToken(token, auth);
		return token;
	}

	private OAuth2Authentication accuireAuthentication(OAuth2AccessToken token) {
		// get JWT token from auth server.
		OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource);
		restTemplate.getOAuth2ClientContext().setAccessToken(token);
		String jwtToken = restTemplate.getForObject(userInfoUri, String.class);
		OAuth2Authentication authentication = jwtTokenServices.loadAuthentication(jwtToken);

		// work-around: JWT does not carry the principal as User, but as String.
		// sparklr apps needs to have User principals to verify the grant
		Authentication userAuth = authentication.getUserAuthentication();
		User user = new User(userAuth.getName(), "", userAuth.getAuthorities()); // needs password != null
		authentication = new OAuth2Authentication(authentication.getOAuth2Request(),
				new UsernamePasswordAuthenticationToken(user, userAuth.getCredentials(), userAuth.getAuthorities()));
		authentication.setAuthenticated(true);

		return authentication;
	}
}
