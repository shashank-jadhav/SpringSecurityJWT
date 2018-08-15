package com.shashank.auth.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shashank.auth.custom.dto.JsonAuthenticationResponseWriterUtil;
import com.shashank.auth.custom.dto.LoginFailureResponse;
import com.shashank.auth.custom.dto.LoginRequest;
import com.shashank.auth.custom.dto.LoginSuccessResponse;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {
		try {
			LoginRequest creds = new ObjectMapper().readValue(req.getInputStream(), LoginRequest.class);

			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(),
					creds.getPassword(), new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {

		log.info("Inside JWTAuthenticationFilter#successfulAuthentication");

		LoginSuccessResponse loginSuccessResponse = new LoginSuccessResponse();

		String token = Jwts.builder()
				.setSubject(((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername())
				.setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SecurityConstants.SECRET).compact();
		res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
		res.setStatus(HttpServletResponse.SC_OK);
		res.setContentType("application/json");
		loginSuccessResponse
				.setUsername(((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername());
		JsonAuthenticationResponseWriterUtil.writeJsonModelToHttpServletResponse(res, loginSuccessResponse);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		log.info("Inside JWTAuthenticationFilter#unsuccessfulAuthentication");
		LoginFailureResponse loginFailureResponse = new LoginFailureResponse();
		if (exception instanceof BadCredentialsException) {
			loginFailureResponse.setMessage(exception.getMessage());
		} else if (exception instanceof DisabledException) {
			loginFailureResponse.setMessage(exception.getMessage());
		} else if (exception instanceof AuthenticationServiceException) {
			loginFailureResponse.setMessage(exception.getMessage());
		}
		JsonAuthenticationResponseWriterUtil.writeJsonModelToHttpServletResponse(response, loginFailureResponse);

	}

}
