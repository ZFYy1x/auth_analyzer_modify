package com.protect7.authanalyzer.entities;

import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;

public class OriginalRequestResponse implements Comparable<OriginalRequestResponse>{
	
	private final int id;
	private final HttpExchange requestResponse;
	private final String method;
	private final String host;
	private final String url;
	private final String fullUrl;
	private final String infoText;
	private String comment = "";
	private final int statusCode;
	private final int responseContentLength;
	private boolean marked = false;
	
	public OriginalRequestResponse(int id, HttpExchange requestResponse, String method,
			String url, String infoText, int statusCode, int responseContentLength) {
		this.id = id;
		this.requestResponse = requestResponse;
		this.method = method;
		this.host = requestResponse.getHttpService().host();
		this.url = url;
		this.fullUrl = buildFullUrl();
		this.infoText = infoText;
		this.statusCode = statusCode;
		this.responseContentLength = responseContentLength;
	}
	public String getEndpoint() {
		return method + host + url;
	}
	public int getId() {
		return id;
	}
	public HttpExchange getRequestResponse() {
		return requestResponse;
	}
	public String getMethod() {
		return method;
	}
	public String getHost() {
		return host;
	}
	public String getUrl() {
		return url;
	}
	
	public String getFullUrl() {
		return fullUrl;
	}
	
	private String buildFullUrl() {
		// 构建完整的URL，包括协议、主机、端口和路径
		String protocol = MontoyaUtils.protocol(requestResponse.getHttpService());
		String host = requestResponse.getHttpService().host();
		int port = requestResponse.getHttpService().port();
		
		// 构建基础URL
		StringBuilder fullUrl = new StringBuilder();
		fullUrl.append(protocol).append("://").append(host);
		
		// 添加端口（如果不是标准端口）
		if ((protocol.equals("http") && port != 80) || (protocol.equals("https") && port != 443)) {
			fullUrl.append(":").append(port);
		}
		
		// 添加路径和查询参数
		fullUrl.append(url);
		
		return fullUrl.toString();
	}
	public boolean isMarked() {
		return marked;
	}
	public void setMarked(boolean marked) {
		this.marked = marked;
	}
	public String getInfoText() {
		return infoText;
	}
	@Override
	public int compareTo(OriginalRequestResponse o) {
		Integer id = this.getId();
		return id.compareTo(o.getId());
	}
	public int getStatusCode() {
		return statusCode;
	}
	public int getResponseContentLength() {
		return responseContentLength;
	}
	public void setComment(String comment) {
		this.comment = comment;
	}
	public String getComment() {
		return comment;
	}		
}
