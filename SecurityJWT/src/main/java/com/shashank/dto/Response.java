package com.shashank.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@Builder
@ToString
public class Response {
	
	private int status;
	private Object data;
	private String message;
	
  
}