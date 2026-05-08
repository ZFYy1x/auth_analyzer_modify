package com.protect7.authanalyzer.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class DataExporter {

	private static DataExporter mInstance = new DataExporter();

	public static synchronized DataExporter getDataExporter() {
		return mInstance;
	}

	public boolean createXML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns,
			boolean doBase64Encode) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Content>");

			// Write Body
			for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
				writer.write("<Message>");
				HttpExchange originalRequestResponse = requestResponse.getRequestResponse();
				StringBuffer row = new StringBuffer();
				HttpRequest originalRequestInfo = originalRequestResponse.getRequest();
				for (MainColumn column : mainColumns) {
					row.append("<"
							+ column.getName().replace(" ", "_") + ">" + setIntoCDATA(getCellValue(column,
									requestResponse.getId(), originalRequestInfo, originalRequestResponse, requestResponse.getComment()))
							+ "</" + column.getName().replace(" ", "_") + ">\n");
				}
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						String data;
						if ((column == SessionColumn.REQUEST || column == SessionColumn.RESPONSE) && doBase64Encode) {
							data = Base64.getEncoder().encodeToString(getCellValue(column, requestResponse.getId(),
									originalRequestResponse, null).getBytes());
						} else {
							data = setIntoCDATA(getCellValue(column, requestResponse.getId(),
									originalRequestResponse, null));
						}
						row.append("<Original_" + column.getName().replace(" ", "_") + ">" + data + "</Original_"
								+ column.getName().replace(" ", "_") + ">\n");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap()
							.get(requestResponse.getId());
					for (SessionColumn column : sessionColumns) {
						String data;
						if ((column == SessionColumn.REQUEST || column == SessionColumn.RESPONSE) && doBase64Encode) {
							data = Base64.getEncoder()
									.encodeToString(setIntoCDATA(getCellValue(column, requestResponse.getId(),
											sessionRequestResponse.getRequestResponse(),
											sessionRequestResponse.getStatus())).getBytes());
						} else {
							data = setIntoCDATA(getCellValue(column, requestResponse.getId(),
									sessionRequestResponse.getRequestResponse(), sessionRequestResponse.getStatus()));
						}
						row.append("<" + session.getName().replace(" ", "_") + "_" + column.getName().replace(" ", "_")
								+ ">" + data + "</" + session.getName().replace(" ", "_") + "_"
								+ column.getName().replace(" ", "_") + ">\n");
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</Message>\n");
			}
			writer.write("</Content>");
			writer.close();
		} catch (IOException e) {
			MontoyaUtils.logError("Error. Can not write data to XML file. " + e.getMessage());
			return false;
		}
		return true;
	}

	public boolean createHTML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<html><style>\r\n" + "table{table-layout:auto;width:100%;font-family: Arial, sans-serif;}\r\n"
					+ "th{padding-top:12px;padding-bottom:12px;text-align:left;background-color:#747272;color:white;}\r\n"
					+ "tr:nth-child(even){background-color:#f2f2f2;}td,th{border:1px solid #ddd;padding:8px;}\r\n"
					+ "div{max-width:600px;max-height:300px;overflow-y:auto;word-wrap:break-word;}\r\n"
					+ "</style><table><tr>");
			// Write Title
			StringBuffer titleRow = new StringBuffer();
			for (MainColumn column : mainColumns) {
				titleRow.append("<th>" + encodeHTML(column.getName()) + "</th>");
			}
			for (SessionColumn column : sessionColumns) {
				if (column != SessionColumn.BYPASS_STATUS) {
					titleRow.append("<th>" + encodeHTML("Original " + column.getName()) + "</th>");
				}
			}
			for (Session session : sessions) {
				for (SessionColumn column : sessionColumns) {
					titleRow.append("<th>" + encodeHTML(session.getName() + " " + column.getName()) + "</th>");
				}
			}
			titleRow.deleteCharAt(titleRow.length() - 1);
			writer.write(titleRow.toString());
			writer.write("<tr>\n");

			// Write Body
			for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
				writer.write("<tr>");
				HttpExchange originalRequestResponse = requestResponse.getRequestResponse();
				StringBuffer row = new StringBuffer();
				HttpRequest originalRequestInfo = null;
				if(originalRequestResponse != null) {
					originalRequestInfo = originalRequestResponse.getRequest();
				}
				for (MainColumn column : mainColumns) {
					row.append("<td><div>" + encodeHTML(
							getCellValue(column, requestResponse.getId(), originalRequestInfo, originalRequestResponse, requestResponse.getComment()))
							+ "</div></td>");
				}
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						row.append("<td><div>" + encodeHTML(getCellValue(column, requestResponse.getId(),
								originalRequestResponse, null)) + "</div></td>");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap()
							.get(requestResponse.getId());
					for (SessionColumn column : sessionColumns) {
						String startTag = "<td><div class='message'>" ;
						String cellValue = getCellValue(column, requestResponse.getId(),
								sessionRequestResponse.getRequestResponse(),
								sessionRequestResponse.getStatus());
						String endTag = "</div></td>";
						if(column == SessionColumn.BYPASS_STATUS) {
							if(cellValue.equals(BypassConstants.SAME.getName())) {
								startTag = "<td style='background-color: rgba(255, 0, 0, 0.3)'><div class='message'>" ;
							}
							if(cellValue.equals(BypassConstants.SIMILAR.getName())) {
								startTag = "<td style='background-color:rgba(255, 165, 0, 0.3)'><div class='message'>" ;
							}
							if(cellValue.equals(BypassConstants.DIFFERENT.getName())) {
								startTag = "<td style='background-color:rgba(0, 255, 0, 0.3)'><div class='message'>" ;
							}
						}
						row.append(startTag + encodeHTML(cellValue) + endTag);
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</tr>\n");
			}
			writer.write("</table><br>Generated by "+ Globals.EXTENSION_NAME +" Version " + Globals.VERSION + "</html>");
			writer.close();
		} catch (IOException e) {
			MontoyaUtils.logError("Error. Can not write data to HTML file. " + e.getMessage());
			return false;
		}
		return true;
	}

	private String encodeHTML(String text) {
		return text.replaceAll("<", "&lt;").replace("\n", "<br>");
	}

	private String setIntoCDATA(String text) {
		return "<![CDATA[" + text.replace("]]>", "]]><![CDATA[") + "]]>";
	}

	private String getCellValue(MainColumn column, Integer id, HttpRequest requestInfo,
			HttpExchange requestResponse, String comment) {
		switch (column) {
		case ID:
			return String.valueOf(id);
		case METHOD:
			return requestInfo.method();
		case HOST:
			return requestResponse.getHttpService().host();
		case PATH:
			return MontoyaUtils.pathAndQuery(requestInfo);
		case FULL_URL:
			return requestInfo.url();
		case COMMENT:
			return comment;
		default:
			return null;
		}
	}

	private String getCellValue(SessionColumn column, Integer id,
			HttpExchange requestResponse, BypassConstants bypassStatus) {
		HttpResponse responseInfo = requestResponse == null ? null : requestResponse.getResponse();
		switch (column) {
		case BYPASS_STATUS:
			return bypassStatus.getName();
		case REQUEST:
			if(requestResponse != null && requestResponse.getRequestBytes() != null) {
				return new String(requestResponse.getRequestBytes());
			}
			else {
				return "";
			}
		case RESPONSE:
			if(requestResponse != null  && requestResponse.getResponseBytes() != null) {
				return new String(requestResponse.getResponseBytes());
			}
			else {
				return "";
			}
		case STATUS_CODE:
			if(responseInfo != null) {
				return String.valueOf(responseInfo.statusCode());
			}
			else {
				return "-1";
			}
		case CONTENT_LENGTH:
			if(responseInfo != null && requestResponse.getResponseBytes() != null) {
				return String.valueOf(MontoyaUtils.responseBodyLength(responseInfo));
			}
			else {
				return "-1";
			}
		default:
			return null;
		}
	}

	public enum MainColumn {

		ID("ID"), METHOD("方法"), HOST("主机"), PATH("路径"), FULL_URL("完整URL"), COMMENT("评论");

		private final String name;

		public String getName() {
			return this.name;
		}

		private MainColumn(String name) {
			this.name = name;
		}
	}

	public enum SessionColumn {

		BYPASS_STATUS("绕过状态"), STATUS_CODE("状态码"), CONTENT_LENGTH("内容长度"),
		REQUEST("请求"), RESPONSE("响应");

		private String name;

		// getter method
		public String getName() {
			return this.name;
		}

		private SessionColumn(String name) {
			this.name = name;
		}
	}
}
