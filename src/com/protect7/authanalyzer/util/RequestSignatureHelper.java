package com.protect7.authanalyzer.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;

public class RequestSignatureHelper {

	private static final Set<String> DEFAULT_IGNORED_PARAMS = new HashSet<String>(Arrays.asList(
			"_", "ts", "t", "nonce", "cb", "cacheBust", "fbclid", "gclid"));

	private static boolean isIgnoredParam(String key) {
		if (key == null) {
			return true;
		}
		String lower = key.toLowerCase();
		if (DEFAULT_IGNORED_PARAMS.contains(lower)) {
			return true;
		}
		// simple wildcard: utm_*
		if (lower.startsWith("utm_")) {
			return true;
		}
		return false;
	}

	public static String computeMultiDimSignature(OriginalRequestResponse orr) {
		byte[] requestBytes = null;
		if (orr.getRequestResponse() != null) {
			requestBytes = orr.getRequestResponse().getRequestBytes();
		}
		return computeMultiDimSignature(orr.getMethod(), orr.getHost(), orr.getUrl(), requestBytes);
	}

	public static String computeMultiDimSignature(String method, String host, String url, byte[] requestBytes) {
		// url is path + optional query
		String path = extractPath(url);
		String query = extractQuery(url);
		String queryHash = normalizeAndHashQuery(query);
		boolean hasBodyMethod = method != null && !(method.equalsIgnoreCase("GET") || method.equalsIgnoreCase("HEAD"));
		String bodyHash = "";
		if (hasBodyMethod && requestBytes != null) {
				String contentType = extractHeader(requestBytes, "Content-Type");
				int bodyStart = bodyStart(requestBytes);
				int bodyLength = requestBytes.length - bodyStart;
				if (contentType != null && contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
					String form = new String(requestBytes, bodyStart, bodyLength, StandardCharsets.ISO_8859_1);
					bodyHash = normalizeAndHashQuery(form);
				} else {
					// Fallback: hash raw body for json/multipart/binary
					bodyHash = sha256Hex(requestBytes, bodyStart, bodyLength);
				}
		}
		String base = safe(method) + safe(host) + safe(path) + "?" + queryHash;
		if (bodyHash != null && !bodyHash.equals("")) {
			base += "." + bodyHash;
		}
		return base;
	}

	private static String extractPath(String url) {
		if (url == null) return "";
		int q = url.indexOf('?');
		String path = q >= 0 ? url.substring(0, q) : url;
		if (path.length() > 1 && path.endsWith("/")) {
			path = path.substring(0, path.length() - 1);
		}
		return path;
	}

	private static String extractQuery(String url) {
		if (url == null) return "";
		int q = url.indexOf('?');
		return q >= 0 ? url.substring(q + 1) : "";
	}

	private static String normalizeAndHashQuery(String query) {
		if (query == null || query.isEmpty()) {
			return "-";
		}
		Map<String, List<String>> map = new HashMap<String, List<String>>();
		String[] pairs = query.split("&");
		for (String p : pairs) {
			if (p.isEmpty()) continue;
			String[] kv = p.split("=", 2);
			String k = urlDecode(kv[0]).trim();
			String v = kv.length > 1 ? urlDecode(kv[1]) : "";
			if (isIgnoredParam(k)) continue;
			String key = k.toLowerCase();
			if (!map.containsKey(key)) {
				map.put(key, new ArrayList<String>());
			}
			map.get(key).add(v);
		}
		// sort keys and values
		String[] keys = map.keySet().toArray(new String[0]);
		Arrays.sort(keys);
		StringBuilder sb = new StringBuilder();
		for (String k : keys) {
			List<String> vals = map.get(k);
			String[] arr = vals.toArray(new String[0]);
			Arrays.sort(arr);
			for (String v : arr) {
				sb.append(k).append("=").append(v).append("&");
			}
		}
		String canonical = sb.toString();
		return sha256Hex(canonical.getBytes(StandardCharsets.UTF_8));
	}

	private static String urlDecode(String s) {
		try {
			return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
		}
		catch (Exception e) {
			return s;
		}
	}

	private static String extractHeader(byte[] request, String headerName) {
		int headerEnd = indexOf(request, new byte[] {'\r','\n','\r','\n'});
		if (headerEnd < 0) headerEnd = request.length;
		String head = new String(request, 0, headerEnd, StandardCharsets.ISO_8859_1);
		for (String line : head.split("\r\n")) {
			int idx = line.indexOf(':');
			if (idx > 0) {
				String name = line.substring(0, idx).trim();
				if (name.equalsIgnoreCase(headerName)) {
					return line.substring(idx + 1).trim();
				}
			}
		}
		return null;
	}

	private static int bodyStart(byte[] request) {
		int pos = indexOf(request, new byte[] {'\r','\n','\r','\n'});
		if (pos < 0) return request.length;
		int bodyStart = pos + 4;
		if (bodyStart >= request.length) return request.length;
		return bodyStart;
	}

	private static int indexOf(byte[] array, byte[] target) {
		outer: for (int i = 0; i <= array.length - target.length; i++) {
			for (int j = 0; j < target.length; j++) {
				if (array[i + j] != target[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}

	public static String sha256Hex(byte[] data) {
		return sha256Hex(data, 0, data.length);
	}

	public static String sha256Hex(byte[] data, int offset, int length) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(data, offset, length);
			byte[] digest = md.digest();
			StringBuilder sb = new StringBuilder(digest.length * 2);
			for (byte b : digest) {
				String hex = Integer.toHexString((b & 0xFF) | 0x100).substring(1);
				sb.append(hex);
			}
			return sb.toString();
		}
		catch (NoSuchAlgorithmException e) {
			return "";
		}
	}

	private static String safe(String s) {
		return s == null ? "" : s;
	}
}

