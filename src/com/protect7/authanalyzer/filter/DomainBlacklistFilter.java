package com.protect7.authanalyzer.filter;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class DomainBlacklistFilter extends RequestFilter {

	private List<DomainRule> domainRules = Collections.emptyList();

	public DomainBlacklistFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected() && stringLiterals.length > 0) {
			String host = request.httpService() == null ? "" : request.httpService().host().toLowerCase();
			if(host != null && !host.equals("")) {
				for(DomainRule rule : domainRules) {
					if(rule.matches(host)) {
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
		ArrayList<DomainRule> compiled = new ArrayList<DomainRule>();
		if (stringLiterals != null) {
			for(String domain : stringLiterals) {
				DomainRule rule = compileDomainRule(domain);
				if(rule != null) {
					compiled.add(rule);
				}
			}
		}
		domainRules = Collections.unmodifiableList(compiled);
	}

	private DomainRule compileDomainRule(String domain) {
		if(domain == null || domain.trim().equals("")) {
			return null;
		}
		String cleanDomain = domain.trim().toLowerCase();
		if(cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
			try {
				cleanDomain = new URL(cleanDomain).getHost();
			} catch (Exception e) {
				return null;
			}
			if(cleanDomain == null || cleanDomain.equals("")) {
				return null;
			}
			cleanDomain = cleanDomain.toLowerCase();
		}
		if(cleanDomain.startsWith("*.")) {
			return new DomainRule(cleanDomain.substring(2), true);
		}
		if(cleanDomain.startsWith(".")) {
			return new DomainRule(cleanDomain.substring(1), true);
		}
		return new DomainRule(cleanDomain, false);
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}

	private static class DomainRule {
		private final String domain;
		private final boolean suffixRule;

		private DomainRule(String domain, boolean suffixRule) {
			this.domain = domain;
			this.suffixRule = suffixRule;
		}

		private boolean matches(String host) {
			if(suffixRule) {
				return host.equals(domain) || host.endsWith("." + domain);
			}
			return host.equals(domain);
		}
	}
}
