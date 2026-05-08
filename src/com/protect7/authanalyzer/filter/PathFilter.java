package com.protect7.authanalyzer.filter;

import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class PathFilter extends RequestFilter {

	private List<String> pathLiterals = Collections.emptyList();

	public PathFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected() && request.pathWithoutQuery() != null) {
			String url = request.pathWithoutQuery().toLowerCase();
			for(String stringLiteral : pathLiterals) {
				if(url.contains(stringLiteral)) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}

	@Override
	protected void onFilterStringLiteralsChanged() {
		ArrayList<String> compiled = new ArrayList<String>();
		if (stringLiterals != null) {
			for(String stringLiteral : stringLiterals) {
				if(stringLiteral != null && !stringLiteral.trim().equals("")) {
					compiled.add(stringLiteral.toLowerCase());
				}
			}
		}
		pathLiterals = Collections.unmodifiableList(compiled);
	}
	
	@Override
	public boolean hasStringLiterals() {
		return true;
	}

}
