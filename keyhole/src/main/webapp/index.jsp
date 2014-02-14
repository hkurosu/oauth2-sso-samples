<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
  <title>Keyhole</title>
  <link type="text/css" rel="stylesheet" href="<c:url value="/style.css"/>"/>

  <authz:authorize ifAllGranted="ROLE_USER">
    <script type='text/javascript'>
      function pictureDisplay(json) {
        for (var i = 0; i < json.photos.length; i++) {
          var photo = json.photos[i];
          document.write('<img src="photos/' + photo.id + '" alt="' + photo.name + '">');
        }
      }
    </script>
  </authz:authorize>
</head>
<body>

  <h1>Keyhole (OAuth2 Single Sign On Server)</h1>

  <div id="content">
    <authz:authorize ifNotGranted="ROLE_USER">
      <h2>Login</h2>

   		<p>Once you login, TONR and SPARKLR application will never ask your username and password again.</p>

        <form id="loginForm" name="loginForm" action="<c:url value="/login.do"/>" method="post">
        <p><label>Username: <input type='text' name='j_username' value="marissa"></label></p>
        <p><label>Password: <input type='text' name='j_password' value="koala"></label></p>
           
        <p><input name="login" value="Login" type="submit"></p>
      </form>
    </authz:authorize>
    <authz:authorize ifAllGranted="ROLE_USER">
      <div style="text-align: center"><form action="<c:url value="/logout.do"/>"><input type="submit" value="Logout"></form></div>
      
      <h2>Your Photos</h2>

      <p>
        <script type='text/javascript' src='photos?callback=pictureDisplay&format=json'></script>
      </p>
    </authz:authorize>
  </div>

  <div id="footer">Sample application for <a href="http://github.com/SpringSource/spring-security-oauth" target="_blank">Spring Security OAuth</a></div>


</body>
</html>
