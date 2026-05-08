package com.protect7.authanalyzer.controller;

/**
 * The RequestController processes each HTTP message which is not previously rejected due to filter specification. The RequestController
 * extracts the defined values (CSRF Token and Grep Rules) and modifies the given HTTP Message for each session. Furthermore, the
 * RequestController is responsible for analyzing the response and declare the BYPASS status according to the specified definitions.
 * 
 * @author Simon Reinhart
 */

import java.net.URL;
import java.util.List;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenPriority;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.ExtractionHelper;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.RequestModifHelper;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class RequestController {

	public void analyze(HttpExchange originalRequestResponse) {
		
		// Fail-Safe - Check if messageInfo can be processed
		if (originalRequestResponse == null || originalRequestResponse.getRequest() == null) {
			BurpExtender.api.logging().logToError("Cannot analyze request with null values.");
		} else {
			int mapId = CurrentConfig.getCurrentConfig().getNextMapId();
			HttpRequest originalRequestInfo = originalRequestResponse.getRequest();
			HttpResponse originalResponseInfo = originalRequestResponse.getResponse();
			ExtractionHelper.ResponseExtractionContext originalResponseContext = originalResponseInfo == null ? null
					: ExtractionHelper.responseContext(originalResponseInfo);
			List<String> originalHeaders = MontoyaUtils.requestHeaderLines(originalRequestInfo);
			byte[] originalRequestBytes = originalRequestResponse.getRequestBytes();
			for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
				boolean isFiltered = false;
				if(!session.getStatusPanel().isRunning()) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to paused session.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				}
				else if (session.isFilterRequestsWithSameHeader()
						&& isSameHeader(originalHeaders, session)) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to same header.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				} 
				else if(session.isRestrictToScope() && !scopeMatches(MontoyaUtils.requestUrl(originalRequestInfo), session)) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to scope restriction.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				} 
				if(!isFiltered) {
				
					// Handle Session
					TokenPriority tokenPriority = new TokenPriority();
					byte[] modifiedRequest = RequestModifHelper.getModifiedRequest(originalRequestBytes,
							originalRequestInfo.httpService(), session, tokenPriority);
					// Analyze modifiedRequest
					HttpRequest modifiedRequestInfo = MontoyaUtils.requestFromBytes(originalRequestInfo.httpService(), modifiedRequest);

					List<String> modifiedHeaders = RequestModifHelper.getModifiedHeaders(MontoyaUtils.requestHeaderLines(modifiedRequestInfo), session);
					// Optional: rewrite request-line HTTP version according to the UI setting.
					RequestModifHelper.applyHttpProtocolVersionOverride(modifiedHeaders);
					byte[] message = MontoyaUtils.buildHttpMessage(modifiedHeaders, modifiedRequest, modifiedRequestInfo.bodyOffset());

					// Perform modified request
					HttpRequest sessionRequest = MontoyaUtils.requestFromBytes(originalRequestInfo.httpService(), message);
					HttpRequestResponse sentRequestResponse = BurpExtender.api.http().sendRequest(sessionRequest);
					HttpExchange sessionRequestResponse = HttpExchange.from(sentRequestResponse);
				
					// Analyze Response of modified Request
					if (sessionRequestResponse != null && sessionRequestResponse.getRequest() != null && sessionRequestResponse.getResponse() != null) {
						HttpResponse sessionResponseInfo = sessionRequestResponse.getResponse();
						ExtractionHelper.ResponseExtractionContext sessionResponseContext = ExtractionHelper.responseContext(sessionResponseInfo);
						// Extract Token Values if applicable
						for (Token token : session.getTokens()) {
							boolean success = false;
							if (token.isAutoExtract()) {
								success = ExtractionHelper.extractCurrentTokenValue(sessionResponseContext, token);
							}
							if (token.isFromToString()) {
								success = ExtractionHelper.extractTokenWithFromToString(sessionResponseContext, token);
							}
							if(success) {
								session.getStatusPanel().updateTokenStatus(token);
								// Token value successfully extracted. Set TokenRequestResponse for renew feature.
								if(token.getRequestResponse() == null || token.getPriority() <= tokenPriority.getPriority()) {
									token.setRequestResponse(sessionRequestResponse);
									token.setPriority(tokenPriority.getPriority());
								}
							}
						}
						if(originalRequestResponse.getResponse() != null) {
							BypassConstants bypassConstant = analyzeResponse(originalResponseContext, sessionResponseContext);
							AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
									sessionRequestResponse, bypassConstant, null, sessionResponseInfo.statusCode(),
									sessionResponseContext.bodyLength());
							session.putRequestResponse(mapId, analyzerRequestResponse);
						}
						else {
							AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
									sessionRequestResponse, BypassConstants.NA, null, sessionResponseInfo.statusCode(),
									sessionResponseContext.bodyLength());
							session.putRequestResponse(mapId, analyzerRequestResponse);
						}
					} else {
						AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
								null, BypassConstants.NA, "Session Request / Response is null. Probably no response "
										+ "received from server.", -1, -1);
						session.putRequestResponse(mapId, analyzerRequestResponse);
					}
				}
			}
			String url = MontoyaUtils.pathAndQuery(originalRequestInfo);
			String infoText = null;
			if(originalRequestResponse.getResponse() == null) {
				infoText = "Request Dropped. No Response to show.";
			}
			int originalStatusCode = -1;
			int originalResponseContentLength = -1;
			if(originalResponseInfo != null) {
				originalStatusCode = originalResponseInfo.statusCode();
				originalResponseContentLength = originalResponseContext.bodyLength();
			}
			OriginalRequestResponse requestResponse = new OriginalRequestResponse(mapId, originalRequestResponse, 
					originalRequestInfo.method(), url, infoText, originalStatusCode, originalResponseContentLength);
			CurrentConfig.getCurrentConfig().getTableModel().addNewRequestResponse(requestResponse);		
			GenericHelper.animateBurpExtensionTab();
		}
	}
	
	private boolean scopeMatches(URL url, Session session) {
		URL scopeUrl = session.getScopeUrl();
		if(scopeUrl != null && url != null) {
			if(url.getHost().equals(scopeUrl.getHost()) && url.getProtocol().equals(scopeUrl.getProtocol()) &&
					(url.getPath().equals(scopeUrl.getPath()) || scopeUrl.getPath().equals("") || scopeUrl.getPath().equals("/"))) {
				return true;
			}
		}
		return false;
	}

	public boolean isSameHeader(List<String> headers, Session session) {
		String[] headersToReplace = session.getHeadersToReplace().split("\n");
		for (String headerToReplace : headersToReplace) {
			if (!headers.contains(headerToReplace)) {
				return false;
			}
		}
		return true;
	}


	/*
	 * Bypass if: - Both Responses have same Response Body and Status Code
	 * 
	 * Potential Bypass if: - Both Responses have same Response Code - Both
	 * Responses have +-5% of response body length
	 *
	 */
	public BypassConstants analyzeResponse(HttpResponse originalResponseInfo, HttpResponse sessionResponseInfo) {
		return analyzeResponse(ExtractionHelper.responseContext(originalResponseInfo),
				ExtractionHelper.responseContext(sessionResponseInfo));
	}

	public BypassConstants analyzeResponse(ExtractionHelper.ResponseExtractionContext originalResponseContext,
			ExtractionHelper.ResponseExtractionContext sessionResponseContext) {
		HttpResponse originalResponseInfo = originalResponseContext.responseInfo();
		HttpResponse sessionResponseInfo = sessionResponseContext.responseInfo();
		boolean sameStatusCode = originalResponseInfo.statusCode() == sessionResponseInfo.statusCode();
		boolean sameStatusCanMatch = sameStatusCode || !CurrentConfig.getCurrentConfig().isRespectResponseCodeForSameStatus();
		boolean similarStatusCanMatch = sameStatusCode || !CurrentConfig.getCurrentConfig().isRespectResponseCodeForSimilarStatus();
		if (!sameStatusCanMatch && !similarStatusCanMatch) {
			return BypassConstants.DIFFERENT;
		}

		byte[] originalResponse = null;
		byte[] sessionResponse = null;
		if (sameStatusCanMatch) {
			originalResponse = originalResponseContext.responseBytes();
			sessionResponse = sessionResponseContext.responseBytes();
			if (responseBodiesEqual(originalResponse, originalResponseInfo.bodyOffset(), sessionResponse, sessionResponseInfo.bodyOffset())) {
				return BypassConstants.SAME;
			}
		}
		if (similarStatusCanMatch) {
			if (originalResponse == null) {
				originalResponse = originalResponseContext.responseBytes();
			}
			if (sessionResponse == null) {
				sessionResponse = sessionResponseContext.responseBytes();
			}
			int originalBodyLength = bodyLength(originalResponse, originalResponseInfo.bodyOffset());
			int sessionBodyLength = bodyLength(sessionResponse, sessionResponseInfo.bodyOffset());
			int range = originalBodyLength / (100/CurrentConfig.getCurrentConfig().getDerivationForSimilarStatus());
			int difference = originalBodyLength - sessionBodyLength;
			// Check if difference is in range
			if (difference <= range && difference >= -range) {
				return BypassConstants.SIMILAR;
			}
		}
		return BypassConstants.DIFFERENT;
	}

	private int bodyLength(byte[] responseBytes, int bodyOffset) {
		return responseBytes.length - safeBodyOffset(responseBytes, bodyOffset);
	}

	private boolean responseBodiesEqual(byte[] leftResponse, int leftBodyOffset, byte[] rightResponse, int rightBodyOffset) {
		int leftOffset = safeBodyOffset(leftResponse, leftBodyOffset);
		int rightOffset = safeBodyOffset(rightResponse, rightBodyOffset);
		int bodyLength = leftResponse.length - leftOffset;
		if (bodyLength != rightResponse.length - rightOffset) {
			return false;
		}
		for (int i = 0; i < bodyLength; i++) {
			if (leftResponse[leftOffset + i] != rightResponse[rightOffset + i]) {
				return false;
			}
		}
		return true;
	}

	private int safeBodyOffset(byte[] responseBytes, int bodyOffset) {
		if (bodyOffset < 0) {
			return 0;
		}
		if (bodyOffset > responseBytes.length) {
			return responseBytes.length;
		}
		return bodyOffset;
	}
}
