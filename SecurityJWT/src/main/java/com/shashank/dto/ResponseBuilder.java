package com.shashank.dto;

public class ResponseBuilder {

	private int status;
	private Object data;
	private String message;

	public ResponseBuilder(Builder builder) {

		this.status = builder.status;
		this.data = builder.data;
		this.message = builder.message;
	}

	public int getStatus() {
		return status;
	}

	public Object getData() {
		return data;
	}

	public String getMessage() {
		return message;
	}

	public static class Builder {

		private int status;
		private Object data;
		private String message;

		public Builder() {
			super();
		}

		public Builder status(int status) {
			this.status = status;
			return this;
		}

		public Builder data(Object data) {
			this.data = data;
			return this;
		}

		public Builder message(String message) {
			this.message = message;
			return this;
		}

		public ResponseBuilder build() {
			return new ResponseBuilder(this);
		}

	}

}
