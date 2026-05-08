package com.protect7.authanalyzer.filter;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class MethodFilter extends RequestFilter {
	
	private Set<String> methods = Collections.emptySet();

	public MethodFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"OPTIONS"});
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected()) {		
			String requestMethod = request.method() == null ? "" : request.method().toLowerCase();
			if(methods.contains(requestMethod)) {
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
			for(String method : stringLiterals) {
				if(method != null && !method.trim().equals("")) {
					compiled.add(method.toLowerCase());
				}
			}
		}
		methods = Collections.unmodifiableSet(compiled);
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}
