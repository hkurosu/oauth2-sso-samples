package org.springframework.security.oauth.examples.keyhole.mvc;

import java.security.Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
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

	private final Log logger = LogFactory.getLog(getClass());

	private JwtTokenServices jwtTokenServices;

	@ResponseBody
	@RequestMapping("")
	public String getUser(Principal principal)
	{
		return getJwtToken(principal);
	}
	
	@ResponseBody
	@RequestMapping(value = "", params = "format=json", produces = "application/json")
	public String getUserAsJson(Principal principal)
	{
		String jwtToken = getJwtToken(principal);
		Jwt jwt = JwtHelper.decode(jwtToken);
		logger.debug("User info: " + jwt.getClaims());
		return jwt.getClaims();
	}	

	private String getJwtToken(Principal principal) {
		OAuth2Authentication auth = (OAuth2Authentication) principal;
		OAuth2AccessToken token = jwtTokenServices.createAccessToken(auth);
		return token.getValue();
	}

	public void setJwtTokenServices(JwtTokenServices jwtTokenServices) {
		this.jwtTokenServices = jwtTokenServices;
	}
	
}
