/**
 * 
 */
package org.springframework.security.oauth2.sso.provider.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * @author hkurosu@gmail.com
 *
 */
public class JwtTokenConverter extends JwtTokenServices {

	@Override
	public OAuth2Authentication loadAuthentication(String token) throws AuthenticationException {
		OAuth2Authentication auth = super.loadAuthentication(token);
		// work-around: JWT does not carry the principal as User, but as String.
		Authentication userAuth = auth.getUserAuthentication();
		User user = new User(userAuth.getName(), "", userAuth.getAuthorities()); // needs password != null
		OAuth2Authentication convertedAuth = new OAuth2Authentication(auth.getOAuth2Request(),
				new PreAuthenticatedAuthenticationToken(user, auth.getCredentials(), auth.getAuthorities()));
		convertedAuth.setDetails(user);
		return convertedAuth;
	}

}
