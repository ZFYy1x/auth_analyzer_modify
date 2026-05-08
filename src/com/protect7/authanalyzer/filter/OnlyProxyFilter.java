package com.protect7.authanalyzer.filter;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class OnlyProxyFilter extends RequestFilter {

	public OnlyProxyFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected()) {
			if(toolType == ToolType.PROXY) {
				return false;
			}
			else if(toolType == ToolType.REPEATER) {
				incrementFiltered();
			}
		}
		else {
			//Only allow Repeater beside of Proxy
			if(toolType == ToolType.REPEATER || toolType == ToolType.PROXY) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}
