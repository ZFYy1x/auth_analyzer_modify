package com.protect7.authanalyzer.filter;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.protect7.authanalyzer.montoya.MontoyaUtils;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class FileTypeFilter extends RequestFilter {
	
	private Set<String> normalizedFileTypes = Collections.emptySet();

	public FileTypeFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{"js", "script", "css", "png", "jpg", "jpeg", "gif", "svg", "bmp", "woff", "ico"});
	}
	
	@Override
	public boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response) {
		if(onOffButton.isSelected()) {
			String extension = getPathExtension(request.pathWithoutQuery());
			boolean hasExtension = !extension.equals("");
			if(normalizedFileTypes.contains(extension)) {
				incrementFiltered();
				return true;
			}
			if (hasExtension) {
				return false;
			}
			if(response != null && normalizedFileTypes.contains(MontoyaUtils.mimeName(response.inferredMimeType()).toLowerCase())) {
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
			for(String fileType : stringLiterals) {
				String normalized = normalizeFileType(fileType);
				if (!normalized.equals("")) {
					compiled.add(normalized);
				}
			}
		}
		normalizedFileTypes = Collections.unmodifiableSet(compiled);
	}

	private String getPathExtension(String path) {
		if (path == null) {
			return "";
		}
		String normalizedPath = path.toLowerCase();
		int slashIndex = normalizedPath.lastIndexOf('/');
		int dotIndex = normalizedPath.lastIndexOf('.');
		if (dotIndex <= slashIndex || dotIndex == normalizedPath.length() - 1) {
			return "";
		}
		return normalizedPath.substring(dotIndex + 1);
	}

	private String normalizeFileType(String fileType) {
		if (fileType == null) {
			return "";
		}
		String normalizedFileType = fileType.trim().toLowerCase();
		while (normalizedFileType.startsWith(".")) {
			normalizedFileType = normalizedFileType.substring(1);
		}
		return normalizedFileType;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}
