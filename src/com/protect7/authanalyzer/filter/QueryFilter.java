package com.protect7.authanalyzer.filter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class QueryFilter extends RequestFilter {

	private List<String> queryLiterals = Collections.emptyList();

	public QueryFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected()) {
			if(request.query() != null && !request.query().equals("")) {
				String query = request.query().toLowerCase();
				for(String stringLiteral : queryLiterals) {
					if(query.contains(stringLiteral)) {
						incrementFiltered();
						return true;
					}
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
		queryLiterals = Collections.unmodifiableList(compiled);
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}

}
