package com.protect7.authanalyzer.entities;

import burp.api.montoya.http.HttpService;

public class TokenRequest {
	
	private final int id;
	private final byte[] request;
	private final HttpService httpService;
	private final int priority;
	public TokenRequest(int id, byte[] request, HttpService httpService, int priority) {
		this.id = id;
		this.request = request;
		this.httpService = httpService;
		this.priority = priority;
	}
	public byte[] getRequest() {
		return request;
	}
	public int getPriority() {
		return priority;
	}
	public HttpService getHttpService() {
		return httpService;
	}
	public int getId() {
		return id;
	}
}
