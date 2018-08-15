package com.shashank.auth.custom.dto;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginSuccessResponse implements Serializable {

	private static final long serialVersionUID = -955313357369346482L;

	public LoginSuccessResponse() {
		super();
	}

	private String username;

}