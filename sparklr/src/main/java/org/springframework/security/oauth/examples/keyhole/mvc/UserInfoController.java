/**
 * 
 */
package org.springframework.security.oauth.examples.keyhole.mvc;

import java.security.Principal;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author hirobumi.kurosu
 *
 */
@Controller
public class UserInfoController {

	private UserDetailsService userDetailsService;
	
	@ResponseBody
	@RequestMapping("/userinfo")
	public User getPhotoServiceUser(Principal principal)
	{
		User user = (User)userDetailsService.loadUserByUsername(principal.getName());
		return user;
	}
	
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
	
}
