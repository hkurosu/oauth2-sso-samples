oauth2-sso-samples
==================

Extended Spring OAuth2 tonr/sparklr samples to support Single sign on.

# Getting Started

## Spring framework dependencies

1. spring-* : 3.2.8.RELEASE
1. spring-security : 3.2.3.RELEASE
1. spring-security-oauth2 : 2.0.1.RELEASE
1. spring-security-jwt : 1.0.2.RELEASE
	
## Build samples applications (command line)

"mvn package" in oauth2-sso-samples directory will create three war files (tonr, sparklr, keyhole).

## Run in eclipse

- Import tonr, sparklr, keyhole and oauth2sso projects with "Existing Maven projects" (Import -> Maven)
- If necessary, import also "spring-security-oauth2" and "spring-security-jwt" from spring-security-oauth. (This should not be necessary, but eclipse will 
complain about spring-security-oauth2-2.0.xsd file if they are not imported).

Now you can deploy all 3 apps (tonr2, sparklr2, keyhole2) into your Servers environment!

## Next step

See this document how these sample apps works: [OAuth2 Single Sign On with spring-security-oauth2](
https://github.com/hkurosu/oauth2-sso-samples/blob/master/docs/OAuth2%20Single%20Sign%20On%20with%20Spring%20\(Demo\).pptx)


