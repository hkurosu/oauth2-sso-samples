package org.springframework.security.oauth.examples.keyhole.mvc;

import java.security.Principal;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author hirobumi.kurosu
 */
@RequestMapping("/me")
@Controller
public class UserController {

	private JwtTokenServices jwtTokenServices;

	
	@ResponseBody
	@RequestMapping("")
	public String getUser(Principal principal)
	{
		OAuth2Authentication auth = (OAuth2Authentication) principal;
		OAuth2AccessToken token = jwtTokenServices.createAccessToken(auth);
		return token.getValue();
	}

	public void setJwtTokenServices(JwtTokenServices jwtTokenServices) {
		this.jwtTokenServices = jwtTokenServices;
	}
	
}
