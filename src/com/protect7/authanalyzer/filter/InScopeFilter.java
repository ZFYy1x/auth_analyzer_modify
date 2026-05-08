package com.protect7.authanalyzer.filter;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class InScopeFilter extends RequestFilter {

	public InScopeFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if (onOffButton.isSelected() && !request.isInScope()) {
			incrementFiltered();
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}
