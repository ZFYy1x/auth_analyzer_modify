package com.protect7.authanalyzer.util;

import static burp.api.montoya.http.HttpService.httpService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * 负责读取 DataExporter.createSnapshot 生成的"看板备份"JSON，
 * 并按当前配置的 Session（按名字匹配）把数据覆盖恢复到看板表格。
 *
 * 恢复语义：
 * <ul>
 *   <li>先完整解析并校验备份文件，任何解析错误都会中止（不清空现有数据）；</li>
 *   <li>解析通过后清空当前看板（Session 请求缓存 + 表格行），再按备份重建；</li>
 *   <li>ID 重新从当前计数器分配，避免与后续实时流量冲突；</li>
 *   <li>备份中会话名在当前配置中不存在时，该会话对应的数据被跳过并记录警告。</li>
 * </ul>
 */
public class DataImporter {

	private DataImporter() {
	}

	/** 恢复结果统计。error 为 null 表示成功。 */
	public static class ImportResult {
		public int totalRows = 0;
		public int restoredRows = 0;
		public int skippedInvalidRows = 0;
		public int matchedSessionEntries = 0;
		public int skippedSessionEntries = 0;
		public List<String> unknownSessions = new ArrayList<String>();
		public String error = null;
	}

	/** 备份中单条 Session 结果 */
	private static class ParsedSessionData {
		String sessionName;
		String statusName;
		String infoText;
		int statusCode;
		int responseContentLength;
		byte[] requestBytes;
		byte[] responseBytes;
	}

	/** 备份中一行看板数据 */
	private static class ParsedRow {
		int id;
		String comment;
		boolean marked;
		String infoText;
		String method;
		String url;
		int statusCode;
		int responseContentLength;
		String host;
		int port;
		boolean secure;
		byte[] requestBytes;
		byte[] responseBytes;
		List<ParsedSessionData> sessionData = new ArrayList<ParsedSessionData>();
	}

	public static ImportResult restore(File file, CurrentConfig config, RequestTableModel tableModel) {
		ImportResult result = new ImportResult();
		try {
			List<ParsedRow> rows = parse(file);
			Collections.sort(rows, new Comparator<ParsedRow>() {
				@Override
				public int compare(ParsedRow left, ParsedRow right) {
					return Integer.compare(left.id, right.id);
				}
			});
			result.totalRows = rows.size();

			// 按名字建立当前 Session 索引，并收集缺失会话
			Map<String, Session> sessionsByName = new LinkedHashMap<String, Session>();
			for (Session session : config.getSessions()) {
				sessionsByName.put(session.getName(), session);
			}
			LinkedHashSet<String> unknownSet = new LinkedHashSet<String>();
			for (ParsedRow row : rows) {
				for (ParsedSessionData sessionData : row.sessionData) {
					if (sessionData.sessionName == null
							|| sessionsByName.get(sessionData.sessionName) == null) {
						unknownSet.add(sessionData.sessionName);
					}
				}
			}
			result.unknownSessions.addAll(unknownSet);

			// 解析通过：清空当前看板后重建
			config.clearSessionRequestMaps();
			tableModel.clearRequestMap();

			for (ParsedRow row : rows) {
				try {
					restoreRow(row, sessionsByName, config, result);
				} catch (Exception rowException) {
					result.skippedInvalidRows++;
					MontoyaUtils.logError("Skipped row (id " + row.id + ") during snapshot restore. "
							+ rowException.getMessage());
				}
			}
		} catch (Exception e) {
			result.error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
			MontoyaUtils.logError("Board snapshot restore failed. " + result.error);
		}
		return result;
	}

	private static void restoreRow(ParsedRow row, Map<String, Session> sessionsByName, CurrentConfig config,
			ImportResult result) {
		if (row.requestBytes == null || row.requestBytes.length == 0 || row.host == null || row.host.isEmpty()) {
			result.skippedInvalidRows++;
			return;
		}
		int effectivePort = row.port;
		if (effectivePort <= 0) {
			effectivePort = row.secure ? 443 : 80;
		}
		HttpService service = httpService(row.host, effectivePort, row.secure);
		HttpRequest request = MontoyaUtils.requestFromBytes(service, row.requestBytes);
		if (request == null) {
			result.skippedInvalidRows++;
			return;
		}
		HttpResponse response = MontoyaUtils.responseFromBytes(row.responseBytes);
		HttpExchange exchange = new HttpExchange(request, response);
		int newId = config.getNextMapId();
		OriginalRequestResponse originalRequestResponse = new OriginalRequestResponse(newId, exchange,
				row.method == null ? request.method() : row.method,
				row.url == null ? MontoyaUtils.pathAndQuery(request) : row.url, row.infoText, row.statusCode,
				row.responseContentLength);
		if (row.comment != null) {
			originalRequestResponse.setComment(row.comment);
		}
		originalRequestResponse.setMarked(row.marked);
		config.getTableModel().addNewRequestResponse(originalRequestResponse);
		result.restoredRows++;

		for (ParsedSessionData sessionData : row.sessionData) {
			Session session = sessionData.sessionName == null ? null : sessionsByName.get(sessionData.sessionName);
			if (session == null) {
				result.skippedSessionEntries++;
				continue;
			}
			HttpExchange sessionExchange = null;
			if (sessionData.requestBytes != null && sessionData.requestBytes.length > 0) {
				HttpRequest sessionRequest = MontoyaUtils.requestFromBytes(service, sessionData.requestBytes);
				if (sessionRequest != null) {
					sessionExchange = new HttpExchange(sessionRequest,
							MontoyaUtils.responseFromBytes(sessionData.responseBytes));
				}
			}
			BypassConstants status = null;
			if (sessionData.statusName != null) {
				try {
					status = BypassConstants.valueOf(sessionData.statusName);
				} catch (Exception ignore) {
					status = BypassConstants.NA;
				}
			}
			AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(sessionExchange, status,
					sessionData.infoText, sessionData.statusCode, sessionData.responseContentLength);
			session.putRequestResponse(newId, analyzerRequestResponse);
			result.matchedSessionEntries++;
		}
	}

	private static List<ParsedRow> parse(File file) throws IOException {
		List<ParsedRow> rows = new ArrayList<ParsedRow>();
		JsonReader reader = new JsonReader(
				new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
		try {
			String format = null;
			int version = -1;
			reader.beginObject();
			while (reader.hasNext()) {
				String name = reader.nextName();
				if ("format".equals(name)) {
					format = reader.nextString();
				} else if ("version".equals(name)) {
					version = reader.nextInt();
				} else if ("exportedAt".equals(name)) {
					reader.skipValue();
				} else if ("sessionNames".equals(name)) {
					reader.skipValue();
				} else if ("rows".equals(name)) {
					reader.beginArray();
					while (reader.hasNext()) {
						rows.add(parseRow(reader));
					}
					reader.endArray();
				} else {
					reader.skipValue();
				}
			}
			reader.endObject();
			if (!DataExporter.SNAPSHOT_FORMAT.equals(format)) {
				throw new IOException("文件不是有效的看板备份（format 不匹配）");
			}
			if (version != DataExporter.SNAPSHOT_VERSION) {
				throw new IOException("不支持的备份版本: " + version + "（当前支持 " + DataExporter.SNAPSHOT_VERSION + "）");
			}
		} finally {
			reader.close();
		}
		return rows;
	}

	private static ParsedRow parseRow(JsonReader reader) throws IOException {
		ParsedRow row = new ParsedRow();
		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			if ("id".equals(name)) {
				row.id = reader.nextInt();
			} else if ("comment".equals(name)) {
				row.comment = nextNullableString(reader);
			} else if ("marked".equals(name)) {
				row.marked = reader.nextBoolean();
			} else if ("infoText".equals(name)) {
				row.infoText = nextNullableString(reader);
			} else if ("method".equals(name)) {
				row.method = nextNullableString(reader);
			} else if ("url".equals(name)) {
				row.url = nextNullableString(reader);
			} else if ("statusCode".equals(name)) {
				row.statusCode = reader.nextInt();
			} else if ("responseContentLength".equals(name)) {
				row.responseContentLength = reader.nextInt();
			} else if ("host".equals(name)) {
				row.host = nextNullableString(reader);
			} else if ("port".equals(name)) {
				row.port = reader.nextInt();
			} else if ("secure".equals(name)) {
				row.secure = reader.nextBoolean();
			} else if ("requestB64".equals(name)) {
				row.requestBytes = decodeBase64(nextNullableString(reader), row.id);
			} else if ("responseB64".equals(name)) {
				row.responseBytes = decodeBase64(nextNullableString(reader), row.id);
			} else if ("sessionData".equals(name)) {
				row.sessionData = parseSessionData(reader, row.id);
			} else {
				reader.skipValue();
			}
		}
		reader.endObject();
		return row;
	}

	private static List<ParsedSessionData> parseSessionData(JsonReader reader, int rowId) throws IOException {
		List<ParsedSessionData> sessionDataList = new ArrayList<ParsedSessionData>();
		reader.beginArray();
		while (reader.hasNext()) {
			ParsedSessionData sessionData = new ParsedSessionData();
			reader.beginObject();
			while (reader.hasNext()) {
				String name = reader.nextName();
				if ("sessionName".equals(name)) {
					sessionData.sessionName = nextNullableString(reader);
				} else if ("statusName".equals(name)) {
					sessionData.statusName = nextNullableString(reader);
				} else if ("infoText".equals(name)) {
					sessionData.infoText = nextNullableString(reader);
				} else if ("statusCode".equals(name)) {
					sessionData.statusCode = reader.nextInt();
				} else if ("responseContentLength".equals(name)) {
					sessionData.responseContentLength = reader.nextInt();
				} else if ("requestB64".equals(name)) {
					sessionData.requestBytes = decodeBase64(nextNullableString(reader), rowId);
				} else if ("responseB64".equals(name)) {
					sessionData.responseBytes = decodeBase64(nextNullableString(reader), rowId);
				} else {
					reader.skipValue();
				}
			}
			reader.endObject();
			sessionDataList.add(sessionData);
		}
		reader.endArray();
		return sessionDataList;
	}

	private static String nextNullableString(JsonReader reader) throws IOException {
		if (reader.peek() == JsonToken.NULL) {
			reader.nextNull();
			return null;
		}
		return reader.nextString();
	}

	private static byte[] decodeBase64(String value, int rowId) {
		if (value == null) {
			return null;
		}
		try {
			return Base64.getDecoder().decode(value);
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException("行 " + rowId + " 的 Base64 数据损坏: " + e.getMessage());
		}
	}
}
