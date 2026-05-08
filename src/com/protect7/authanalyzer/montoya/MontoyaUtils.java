package com.protect7.authanalyzer.montoya;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.http.HttpService.httpService;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;

import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public final class MontoyaUtils {

	private MontoyaUtils() {
	}

	public static HttpRequest requestFromBytes(HttpService service, byte[] requestBytes) {
		if (requestBytes == null) {
			return null;
		}
		if (service == null) {
			return httpRequest(byteArray(requestBytes));
		}
		return httpRequest(service, byteArray(requestBytes));
	}

	public static HttpRequest requestFromUrl(URL url) {
		String path = url.getPath();
		if (path == null || path.equals("")) {
			path = "/";
		}
		if (url.getQuery() != null) {
			path += "?" + url.getQuery();
		}
		String request = "GET " + path + " HTTP/1.1\r\nHost: " + url.getHost() + "\r\n\r\n";
		int port = url.getPort();
		if (port == -1) {
			port = "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
		}
		return httpRequest(httpService(url.getHost(), port, "https".equalsIgnoreCase(url.getProtocol())),
				byteArray(request.getBytes(StandardCharsets.ISO_8859_1)));
	}

	public static HttpResponse responseFromBytes(byte[] responseBytes) {
		return responseBytes == null ? null : httpResponse(byteArray(responseBytes));
	}

	public static byte[] buildHttpMessage(List<String> headers, byte[] body) {
		return buildHttpMessage(headers, body, 0, body == null ? 0 : body.length);
	}

	public static byte[] buildHttpMessage(List<String> headers, byte[] message, int bodyOffset) {
		if (message == null) {
			return buildHttpMessage(headers, (byte[]) null);
		}
		int safeOffset = bodyOffset;
		if (safeOffset < 0) {
			safeOffset = 0;
		}
		if (safeOffset > message.length) {
			safeOffset = message.length;
		}
		return buildHttpMessage(headers, message, safeOffset, message.length - safeOffset);
	}

	private static byte[] buildHttpMessage(List<String> headers, byte[] body, int bodyOffset, int bodyLength) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			for (String header : headers) {
				out.write(header.getBytes(StandardCharsets.ISO_8859_1));
				out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
			}
			out.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
			if (body != null && bodyLength > 0) {
				out.write(body, bodyOffset, bodyLength);
			}
		}
		catch (Exception e) {
			return new byte[0];
		}
		return out.toByteArray();
	}

	public static List<String> requestHeaderLines(HttpRequest request) {
		if (request == null) {
			return new ArrayList<String>();
		}
		byte[] requestBytes = request.toByteArray().getBytes();
		List<String> parsed = headerLines(requestBytes, request.bodyOffset());
		if (!parsed.isEmpty()) {
			return parsed;
		}
		List<String> headers = new ArrayList<String>();
		headers.add(request.method() + " " + request.path() + " " + request.httpVersion());
		for (HttpHeader header : request.headers()) {
			headers.add(header.toString());
		}
		return headers;
	}

	private static List<String> headerLines(byte[] message, int bodyOffset) {
		int headerLength = bodyOffset;
		if (headerLength >= 4 && message[headerLength - 4] == '\r') {
			headerLength -= 4;
		}
		else if (headerLength >= 2) {
			headerLength -= 2;
		}
		if (headerLength <= 0) {
			return new ArrayList<String>();
		}
		String headerBlock = new String(message, 0, headerLength, StandardCharsets.ISO_8859_1);
		return new ArrayList<String>(Arrays.asList(headerBlock.replace("\r", "").split("\n")));
	}

	public static URL requestUrl(HttpRequest request) {
		try {
			return new URL(request.url());
		}
		catch (MalformedURLException e) {
			try {
				HttpService service = request.httpService();
				String protocol = protocol(service);
				String host = service == null ? "placeholder.invalid" : service.host();
				int port = service == null ? -1 : service.port();
				String path = request.path() == null || request.path().equals("") ? "/" : request.path();
				if ((protocol.equals("http") && port == 80) || (protocol.equals("https") && port == 443) || port <= 0) {
					return new URL(protocol + "://" + host + path);
				}
				return new URL(protocol + "://" + host + ":" + port + path);
			}
			catch (MalformedURLException impossible) {
				return null;
			}
		}
	}

	public static String protocol(HttpService service) {
		return service != null && service.secure() ? "https" : "http";
	}

	public static String pathAndQuery(HttpRequest request) {
		URL url = requestUrl(request);
		if (url == null) {
			return request.path();
		}
		if (url.getQuery() == null) {
			return url.getPath();
		}
		return url.getPath() + "?" + url.getQuery();
	}

	public static int responseBodyLength(HttpResponse response) {
		if (response == null) {
			return -1;
		}
		byte[] responseBytes = response.toByteArray().getBytes();
		return responseBytes.length - response.bodyOffset();
	}

	public static String mimeName(MimeType mimeType) {
		if (mimeType == null || mimeType == MimeType.NONE || mimeType == MimeType.UNRECOGNIZED) {
			return "";
		}
		if (mimeType == MimeType.PLAIN_TEXT) {
			return "TEXT";
		}
		if (mimeType == MimeType.IMAGE_JPEG) {
			return "JPEG";
		}
		if (mimeType == MimeType.IMAGE_GIF) {
			return "GIF";
		}
		if (mimeType == MimeType.IMAGE_PNG) {
			return "PNG";
		}
		if (mimeType == MimeType.IMAGE_BMP) {
			return "BMP";
		}
		if (mimeType == MimeType.IMAGE_SVG_XML) {
			return "SVG";
		}
		if (mimeType == MimeType.FONT_WOFF) {
			return "WOFF";
		}
		if (mimeType == MimeType.FONT_WOFF2) {
			return "WOFF2";
		}
		return mimeType.name();
	}

	public static ContentType contentType(HttpRequest request) {
		return request == null ? ContentType.NONE : request.contentType();
	}

	public static void logOutput(String message) {
		burp.BurpExtender.api.logging().logToOutput(message);
	}

	public static void logError(String message) {
		burp.BurpExtender.api.logging().logToError(message);
	}
}
