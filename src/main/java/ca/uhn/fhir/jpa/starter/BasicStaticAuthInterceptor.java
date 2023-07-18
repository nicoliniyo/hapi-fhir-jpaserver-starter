package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
@Interceptor
public class BasicStaticAuthInterceptor {
	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory.getLogger(BasicStaticAuthInterceptor.class);

	@Value("${hapi.fhir.username}")
	private String basicAuthUsername;

	@Value("${hapi.fhir.password}")
	private String basicAuthPassword;

	public BasicStaticAuthInterceptor(String basicAuthUsername, String basicAuthPassword) {
		this.basicAuthUsername = basicAuthUsername;
		this.basicAuthPassword = basicAuthPassword;
	}

	/**
	 * This interceptor implements HTTP Basic Auth, which specifies that
	 * a username and password are provided in a header called Authorization.
	 */
	@Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
	public boolean incomingRequestPostProcessed(RequestDetails theRequestDetails, HttpServletRequest theRequest, HttpServletResponse theResponse) throws AuthenticationException {
		String requestPath = theRequestDetails.getRequestPath();
		ourLog.info("requestPath: {}", requestPath);
		if(requestPath.contains("metadata")) {
			return true;
		}
		String authHeader = theRequest.getHeader("Authorization");
		// Authorization: Basic [base64 of username:password]
		if (authHeader == null || authHeader.startsWith("Basic ") == false) {
			throw new AuthenticationException(Msg.code(642) + "Missing or invalid Authorization header");
		}
		String authHeaderBase64 = authHeader.substring("Basic ".length());
		String usPass = new String(Base64.encodeBase64(new String(basicAuthUsername + ":" + basicAuthPassword).getBytes()));
		if (!authHeaderBase64.equals(new String(usPass))) {
			throw new AuthenticationException(Msg.code(643) + "Invalid username or password");
		}
		// Return true to allow the request to proceed
		return true;
	}
}

