package com.protect7.authanalyzer.controller;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.util.CurrentConfig;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

public class HttpListener implements HttpHandler, ProxyRequestHandler {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
		return RequestToBeSentAction.continueWith(requestToBeSent);
	}

	@Override
	public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
		if (config.isRunning()) {
			HttpRequest request = responseReceived.initiatingRequest();
			HttpResponse response = responseReceived;
			HttpRequestResponse requestResponse = httpRequestResponse(request, response);
			ToolType toolType = responseReceived.toolSource().toolType();
			if (!isFiltered(toolType, request, response)) {
				config.performAuthAnalyzerRequest(HttpExchange.from(requestResponse));
			}
		}
		return ResponseReceivedAction.continueWith(responseReceived);
	}

	@Override
	public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
		if (config.isDropOriginal() && config.isRunning()) {
			if (!isFiltered(ToolType.PROXY, interceptedRequest, null)) {
				config.performAuthAnalyzerRequest(HttpExchange.from(interceptedRequest));
				return ProxyRequestReceivedAction.drop();
			}
		}
		return ProxyRequestReceivedAction.continueWith(interceptedRequest);
	}

	@Override
	public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
		return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
	}

	private boolean isFiltered(ToolType toolType, HttpRequest request, HttpResponse response) {
		for (int i = 0; i < config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if (filter.filterRequest(toolType, request, response)) {
				return true;
			}
		}
		return false;
	}
}
