package org.springframework.security.oauth.examples.keyhole.model;

//
// copied from sparklr PhotoServiceUser
//

/**
 * @author hirobumi.kurosu
 * 
 */
public class UserInfo {
	
	private String username;
	private String name;
	
	public UserInfo() {
	}
	
	/**
	 * Create a new PhotoServiceUser
	 *
	 * @param username The unique username for the user
	 * @param name The name of the user
	 */
	public UserInfo(String username,String name)
	{
		this.username = username;
		this.name = name;
	}

	/**
	 * The unique username for the user
	 *
	 * @return username of the user
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * The name of the user
	 *
	 * @return name of the user
	 */
	public String getName() {
		return name;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setName(String name) {
		this.name = name;
	}
}
