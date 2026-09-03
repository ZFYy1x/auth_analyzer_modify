package com.protect7.authanalyzer.montoya;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class HttpExchange {

	private final HttpRequest request;
	private final HttpResponse response;
	// 惰性字节缓存：montoya 的 HttpRequest/HttpResponse 不可变，
	// 因此 toByteArray() 的结果可安全缓存，避免大流量下反复全量序列化。
	private volatile byte[] cachedRequestBytes;
	private volatile byte[] cachedResponseBytes;

	public HttpExchange(HttpRequest request, HttpResponse response) {
		this.request = request;
		this.response = response;
	}

	public static HttpExchange from(HttpRequest request) {
		return new HttpExchange(request, null);
	}

	public static HttpExchange from(HttpRequest request, HttpResponse response) {
		return new HttpExchange(request, response);
	}

	public static HttpExchange from(HttpRequestResponse requestResponse) {
		if (requestResponse == null) {
			return null;
		}
		return new HttpExchange(requestResponse.request(),
				requestResponse.hasResponse() ? requestResponse.response() : null);
	}

	public HttpRequest getRequest() {
		return request;
	}

	public HttpResponse getResponse() {
		return response;
	}

	public boolean hasResponse() {
		return response != null;
	}

	public HttpService getHttpService() {
		return request == null ? null : request.httpService();
	}

	public byte[] getRequestBytes() {
		if (request == null) {
			return null;
		}
		byte[] cached = cachedRequestBytes;
		if (cached == null) {
			cached = request.toByteArray().getBytes();
			cachedRequestBytes = cached;
		}
		return cached;
	}

	public byte[] getResponseBytes() {
		if (response == null) {
			return null;
		}
		byte[] cached = cachedResponseBytes;
		if (cached == null) {
			cached = response.toByteArray().getBytes();
			cachedResponseBytes = cached;
		}
		return cached;
	}
}
