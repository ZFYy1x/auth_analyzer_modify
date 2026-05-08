package com.protect7.authanalyzer.filter;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class StatusCodeFilter extends RequestFilter {
	
	private Set<String> statusCodes = Collections.emptySet();

	public StatusCodeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"304"});
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if (onOffButton.isSelected() && response != null) {
			String statusCode = String.valueOf(response.statusCode());
			if (statusCodes.contains(statusCode)) {
				incrementFiltered();
				return true;
			}
		}
		return false;
	}

	@Override
	protected void onFilterStringLiteralsChanged() {
		HashSet<String> compiled = new HashSet<String>();
		if (stringLiterals != null) {
			for (String stringLiteral : stringLiterals) {
				if (stringLiteral != null && !stringLiteral.trim().equals("")) {
					compiled.add(stringLiteral.trim().toLowerCase());
				}
			}
		}
		statusCodes = Collections.unmodifiableSet(compiled);
	}
	
	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}
