package com.protect7.authanalyzer.gui.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
// removed unused digest imports
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.RequestSignatureHelper;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 8;
	// Signatures muted (tombstoned) by user deletion so duplicates remain hidden
	private final Set<String> mutedSignatures = new HashSet<String>();
	
	// 批量更新相关字段
	private final ArrayList<OriginalRequestResponse> pendingUpdates = new ArrayList<OriginalRequestResponse>();
	private Timer batchUpdateTimer;
	private static final int BATCH_SIZE = 50; // 批量大小
	private static final int BATCH_DELAY_MS = 100; // 延迟时间
	private volatile boolean batchUpdateScheduled = false;
	
	// 缓存相关字段
	private final Map<Integer, OriginalRequestResponse> requestResponseById = new HashMap<Integer, OriginalRequestResponse>();
	private final Map<Integer, Integer> rowIndexById = new HashMap<Integer, Integer>();
	private final Map<String, TreeMap<Integer, OriginalRequestResponse>> pathRowsById = new HashMap<String, TreeMap<Integer, OriginalRequestResponse>>();
	private final Map<Integer, String> signatureCache = new HashMap<Integer, String>();
	private final Map<String, Integer> signatureFirstIdIndex = new HashMap<String, Integer>();
	private final Set<Integer> duplicateSignatureIdIndex = new HashSet<Integer>();
	
	public ArrayList<OriginalRequestResponse> getOriginalRequestResponseList() {
		return originalRequestResponseList;
	}
	
	public synchronized void addNewRequestResponse(OriginalRequestResponse requestResponse) {
		String pathOnly = "";
		try {
			pathOnly = extractPathOnly(requestResponse.getUrl());
		}
		catch (Exception e) {
			// ignore
		}
		int firstPendingRowIndex = originalRequestResponseList.size() - pendingUpdates.size();
		int insertedRowIndex = originalRequestResponseList.size();
		originalRequestResponseList.add(requestResponse);
		requestResponseById.put(requestResponse.getId(), requestResponse);
		rowIndexById.put(requestResponse.getId(), insertedRowIndex);
		getRowsForPath(pathOnly).put(requestResponse.getId(), requestResponse);
		indexDuplicateSignature(requestResponse);
		Integer previousRepresentativeId = findPreviousVisibleRepresentativeIdForPath(pathOnly, requestResponse.getId());
		ArrayList<Integer> updatedRows;
		if (previousRepresentativeId == null && canRepresentPath(requestResponse)) {
			updatedRows = refreshAutoDuplicateCommentsForPath(pathOnly);
		}
		else {
			updatedRows = new ArrayList<Integer>();
			if (updateAutoDuplicateComment(requestResponse, previousRepresentativeId)) {
				updatedRows.add(insertedRowIndex);
			}
		}
		pendingUpdates.add(requestResponse);
		notifyVisibleRowsUpdated(updatedRows, firstPendingRowIndex);
		
		// 批量更新逻辑
		if (pendingUpdates.size() >= BATCH_SIZE) {
			flushPendingUpdates();
		} else {
			scheduleBatchUpdate();
		}
	}
	
	/**
	 * 立即刷新待更新的数据
	 */
	private synchronized void flushPendingUpdates() {
		if (!pendingUpdates.isEmpty()) {
			int startIndex = originalRequestResponseList.size() - pendingUpdates.size();
			int endIndex = originalRequestResponseList.size() - 1;
			pendingUpdates.clear();
			
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					fireTableRowsInserted(startIndex, endIndex);
				}
			});
		}
		cancelBatchUpdateTimer();
	}
	
	/**
	 * 安排批量更新
	 */
	private synchronized void scheduleBatchUpdate() {
		if (!batchUpdateScheduled) {
			batchUpdateScheduled = true;
			if (batchUpdateTimer != null) {
				batchUpdateTimer.cancel();
			}
			batchUpdateTimer = new Timer("BatchUpdateTimer", true);
			batchUpdateTimer.schedule(new TimerTask() {
				@Override
				public void run() {
					flushPendingUpdates();
					batchUpdateScheduled = false;
				}
			}, BATCH_DELAY_MS);
		}
	}
	
	/**
	 * 取消批量更新定时器
	 */
	private void cancelBatchUpdateTimer() {
		if (batchUpdateTimer != null) {
			batchUpdateTimer.cancel();
			batchUpdateTimer = null;
		}
		batchUpdateScheduled = false;
	}

	private String extractPathOnly(String url) {
		if (url == null) {
			return "";
		}
		String pathOnly = url;
		int q = url.indexOf('?');
		if (q >= 0) {
			pathOnly = url.substring(0, q);
		}
		if (pathOnly.length() > 1 && pathOnly.endsWith("/")) {
			pathOnly = pathOnly.substring(0, pathOnly.length() - 1);
		}
		return pathOnly;
	}

	private TreeMap<Integer, OriginalRequestResponse> getRowsForPath(String pathOnly) {
		TreeMap<Integer, OriginalRequestResponse> rows = pathRowsById.get(pathOnly);
		if (rows == null) {
			rows = new TreeMap<Integer, OriginalRequestResponse>();
			pathRowsById.put(pathOnly, rows);
		}
		return rows;
	}

	private ArrayList<Integer> refreshAutoDuplicateCommentsForPath(String pathOnly) {
		ArrayList<Integer> updatedRows = new ArrayList<Integer>();
		TreeMap<Integer, OriginalRequestResponse> rows = pathRowsById.get(pathOnly);
		if (rows == null || rows.isEmpty()) {
			return updatedRows;
		}
		Integer representativeId = null;
		for (OriginalRequestResponse requestResponse : rows.values()) {
			if (!isAutoDuplicateComment(requestResponse.getComment())) {
				if (representativeId == null && canRepresentPath(requestResponse)) {
					representativeId = requestResponse.getId();
				}
				continue;
			}
			if (updateAutoDuplicateComment(requestResponse, representativeId)) {
				Integer rowIndex = rowIndexById.get(requestResponse.getId());
				if (rowIndex != null) {
					updatedRows.add(rowIndex);
				}
			}
			if (representativeId == null && canRepresentPath(requestResponse)) {
				representativeId = requestResponse.getId();
			}
		}
		return updatedRows;
	}

	private boolean updateAutoDuplicateComment(OriginalRequestResponse requestResponse, Integer representativeId) {
		if (!isAutoDuplicateComment(requestResponse.getComment())) {
			return false;
		}
		String newComment = representativeId == null ? "" : "重复ID:" + representativeId;
		String oldComment = requestResponse.getComment() == null ? "" : requestResponse.getComment();
		if (!oldComment.equals(newComment)) {
			requestResponse.setComment(newComment);
			return true;
		}
		return false;
	}

	private boolean canRepresentPath(OriginalRequestResponse requestResponse) {
		try {
			String signature = getOrComputeSignature(requestResponse);
			return signature != null && signature.length() > 0 && !mutedSignatures.contains(signature);
		}
		catch (Exception e) {
			return false;
		}
	}

	private boolean isAutoDuplicateComment(String comment) {
		return comment == null || comment.length() == 0 || comment.startsWith("重复ID:");
	}

	private void notifyVisibleRowsUpdated(ArrayList<Integer> updatedRows, int firstPendingRowIndex) {
		if (updatedRows.isEmpty()) {
			return;
		}
		Collections.sort(updatedRows);
		int rangeStart = -1;
		int previousRow = -1;
		for (Integer rowIndex : updatedRows) {
			if (rowIndex == null || rowIndex.intValue() >= firstPendingRowIndex || rowIndex.intValue() == previousRow) {
				continue;
			}
			int currentRow = rowIndex.intValue();
			if (rangeStart == -1) {
				rangeStart = currentRow;
				previousRow = currentRow;
				continue;
			}
			if (currentRow == previousRow + 1) {
				previousRow = currentRow;
				continue;
			}
			notifyVisibleRowsUpdated(rangeStart, previousRow);
			rangeStart = currentRow;
			previousRow = currentRow;
		}
		if (rangeStart != -1) {
			notifyVisibleRowsUpdated(rangeStart, previousRow);
		}
	}

	private void notifyVisibleRowsUpdated(int startRow, int endRow) {
		final int modelStartRow = startRow;
		final int modelEndRow = endRow;
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				fireTableRowsUpdated(modelStartRow, modelEndRow);
			}
		});
	}

	private Integer findPreviousVisibleRepresentativeIdForPath(String pathOnly, int currentId) {
		TreeMap<Integer, OriginalRequestResponse> rows = pathRowsById.get(pathOnly);
		if (rows == null || rows.isEmpty()) {
			return null;
		}
		for (OriginalRequestResponse requestResponse : rows.headMap(currentId, false).values()) {
			if (canRepresentPath(requestResponse)) {
				return requestResponse.getId();
			}
		}
		return null;
	}

	private void rebuildRowIndex() {
		rowIndexById.clear();
		for (int rowIndex = 0; rowIndex < originalRequestResponseList.size(); rowIndex++) {
			rowIndexById.put(originalRequestResponseList.get(rowIndex).getId(), rowIndex);
		}
	}
	
	/**
	 * 获取或计算签名，使用缓存
	 */
	private String getOrComputeSignature(OriginalRequestResponse orr) {
		Integer id = orr.getId();
		String cachedSig = signatureCache.get(id);
		if (cachedSig != null) {
			return cachedSig;
		}
		
		String sig = RequestSignatureHelper.computeMultiDimSignature(orr);
		signatureCache.put(id, sig);
		return sig;
	}

	private void indexDuplicateSignature(OriginalRequestResponse requestResponse) {
		try {
			String signature = getOrComputeSignature(requestResponse);
			if (signature == null || signature.length() == 0) {
				return;
			}
			if (mutedSignatures.contains(signature)) {
				signatureFirstIdIndex.remove(signature);
				duplicateSignatureIdIndex.add(requestResponse.getId());
				return;
			}
			Integer firstId = signatureFirstIdIndex.get(signature);
			if (firstId == null) {
				signatureFirstIdIndex.put(signature, requestResponse.getId());
			}
			else if (requestResponse.getId() > firstId.intValue()) {
				duplicateSignatureIdIndex.add(requestResponse.getId());
			}
			else if (requestResponse.getId() < firstId.intValue()) {
				duplicateSignatureIdIndex.add(firstId);
				signatureFirstIdIndex.put(signature, requestResponse.getId());
			}
		}
		catch (Exception ignore) {}
	}

	private void reindexDuplicateSignature(String signature) {
		if (signature == null || signature.length() == 0) {
			return;
		}
		signatureFirstIdIndex.remove(signature);
		ArrayList<OriginalRequestResponse> matchingRows = new ArrayList<OriginalRequestResponse>();
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			try {
				if (signature.equals(getOrComputeSignature(requestResponse))) {
					duplicateSignatureIdIndex.remove(requestResponse.getId());
					matchingRows.add(requestResponse);
				}
			}
			catch (Exception ignore) {}
		}
		Collections.sort(matchingRows, new Comparator<OriginalRequestResponse>() {
			@Override
			public int compare(OriginalRequestResponse left, OriginalRequestResponse right) {
				return Integer.compare(left.getId(), right.getId());
			}
		});
		if (mutedSignatures.contains(signature)) {
			for (OriginalRequestResponse requestResponse : matchingRows) {
				duplicateSignatureIdIndex.add(requestResponse.getId());
			}
			return;
		}
		boolean firstVisibleRowSeen = false;
		for (OriginalRequestResponse requestResponse : matchingRows) {
			if (!firstVisibleRowSeen) {
				signatureFirstIdIndex.put(signature, requestResponse.getId());
				firstVisibleRowSeen = true;
			}
			else {
				duplicateSignatureIdIndex.add(requestResponse.getId());
			}
		}
	}
	
	public boolean isDuplicate(int id, String endpoint) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getEndpoint().equals(endpoint) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks if there is an earlier request with the same Method+Host+Path (ignoring query string).
	 */
	public boolean isDuplicateByEndpointNoQuery(int id, String method, String host, String url) {
		String targetKey = buildEndpointKeyNoQuery(method, host, url);
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			String currentKey = buildEndpointKeyNoQuery(requestResponse.getMethod(), requestResponse.getHost(), requestResponse.getUrl());
			if (currentKey.equals(targetKey) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if there is an earlier request with the same Method+Host+FullUrl (including query string).
	 */
	public boolean isDuplicateByFullUrl(int id, String method, String host, String fullUrl) {
		String targetKey = (method == null ? "" : method) + (host == null ? "" : host) + (fullUrl == null ? "" : fullUrl);
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			String currentFullUrl = requestResponse.getFullUrl();
			String currentKey = requestResponse.getMethod() + requestResponse.getHost() + (currentFullUrl == null ? "" : currentFullUrl);
			if (currentKey.equals(targetKey) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Duplicate check that also considers request body for non-GET methods.
	 * For GET/HEAD, falls back to full URL only. For others, uses full URL + SHA-256 of request bytes.
	 */
	public boolean isDuplicateByRequestSignature(int id, String method, String host, String fullUrl, byte[] requestBytes) {
		if (requestResponseById.containsKey(id)) {
			return isDuplicateByRequestSignature(id);
		}
		String pathPlusQuery = (fullUrl == null) ? "" : fullUrl.substring(fullUrl.indexOf(host) + host.length());
		String targetKey = RequestSignatureHelper.computeMultiDimSignature(method, host, pathPlusQuery, requestBytes);
		if (mutedSignatures.contains(targetKey)) {
			return true;
		}
		Integer firstId = signatureFirstIdIndex.get(targetKey);
		return firstId != null && firstId.intValue() < id;
	}

	public boolean isDuplicateByRequestSignature(int id) {
		return duplicateSignatureIdIndex.contains(id);
	}

	private String buildEndpointKeyNoQuery(String method, String host, String url) {
		String pathOnly = url;
		int q = url == null ? -1 : url.indexOf('?');
		if (q >= 0) {
			pathOnly = url.substring(0, q);
		}
		// Normalize trailing slash: treat "/path" and "/path/" as the same
		if (pathOnly != null && pathOnly.length() > 1 && pathOnly.endsWith("/")) {
			pathOnly = pathOnly.substring(0, pathOnly.length() - 1);
		}
		return (method == null ? "" : method) + (host == null ? "" : host) + (pathOnly == null ? "" : pathOnly);
	}
	
	public void deleteRequestResponse(OriginalRequestResponse requestResponse) {
		String pathOnly = extractPathOnly(requestResponse.getUrl());
		String signature = null;
		try {
			signature = getOrComputeSignature(requestResponse);
			if (signature != null && signature.length() > 0) {
				mutedSignatures.add(signature);
			}
		}
		catch (Exception ignore) {}
		originalRequestResponseList.remove(requestResponse);
		requestResponseById.remove(requestResponse.getId());
		rowIndexById.remove(requestResponse.getId());
		TreeMap<Integer, OriginalRequestResponse> pathRows = pathRowsById.get(pathOnly);
		if (pathRows != null) {
			pathRows.remove(requestResponse.getId());
			if (pathRows.isEmpty()) {
				pathRowsById.remove(pathOnly);
			}
		}
		rebuildRowIndex();
        // 删除后清理相关缓存，避免过滤/重复判断使用过期结果
        try {
            // 清除签名与重复缓存
            signatureCache.remove(requestResponse.getId());
            duplicateSignatureIdIndex.remove(requestResponse.getId());
            reindexDuplicateSignature(signature);
            refreshAutoDuplicateCommentsForPath(pathOnly);
        } catch (Exception ignore) {}
		SwingUtilities.invokeLater(new Runnable() {			
			@Override
			public void run() {
				fireTableDataChanged();
			}
		});
	}
	
	public void clearRequestMap() {
		cancelBatchUpdateTimer();
		originalRequestResponseList.clear();
		pendingUpdates.clear();
		mutedSignatures.clear();
		// 清理缓存
		requestResponseById.clear();
		rowIndexById.clear();
		pathRowsById.clear();
		signatureCache.clear();
		signatureFirstIdIndex.clear();
		duplicateSignatureIdIndex.clear();
		fireTableDataChanged();
	}

	/**
	 * 批量重建（用于从备份恢复看板数据）。
	 *
	 * 与逐行 addNewRequestResponse（面向实时抓流、含逐行自动去重注释扫描与批量 EDT 事件）
	 * 不同，本方法一次性接收整表数据并建立全部内部索引，仅触发一次表格刷新，
	 * 从而在 300+/500+/1000+ 大接口量下显著降低导入耗时的 CPU 与 EDT 开销。
	 *
	 * 调用方约束：
	 * <ul>
	 *   <li>调用前先通过 clearRequestMap() 清空现有看板（本方法不重复清空）；</li>
	 *   <li>传入的行必须已分配新 ID 且按 ID 升序排列（与实时增量语义保持一致，
	 *       使每条签名首个可见行为代表、其余标为重复）；</li>
	 *   <li>行内各 Session 的 AnalyzerRequestResponse 已由调用方写入对应 Session。
	 * </ul>
	 */
	public synchronized void bulkRebuildForRestore(List<OriginalRequestResponse> rows) {
		if (rows == null) {
			return;
		}
		cancelBatchUpdateTimer();
		pendingUpdates.clear();
		for (OriginalRequestResponse requestResponse : rows) {
			if (requestResponse == null) {
				continue;
			}
			int rowIndex = originalRequestResponseList.size();
			originalRequestResponseList.add(requestResponse);
			requestResponseById.put(requestResponse.getId(), requestResponse);
			rowIndexById.put(requestResponse.getId(), rowIndex);
			String pathOnly = "";
			try {
				pathOnly = extractPathOnly(requestResponse.getUrl());
			}
			catch (Exception ignore) {
			}
			getRowsForPath(pathOnly).put(requestResponse.getId(), requestResponse);
		}
		// 建完行后统一计算签名与重复代表，避免逐行操作时路径自动注释扫描的高昂成本
		for (OriginalRequestResponse requestResponse : rows) {
			if (requestResponse == null) {
				continue;
			}
			try {
				indexDuplicateSignature(requestResponse);
			}
			catch (Exception ignore) {
			}
		}
		// 更新每行自动重复注释（"重复ID:x"），使其与实时增量产生的显示一致
		for (OriginalRequestResponse requestResponse : rows) {
			if (requestResponse == null) {
				continue;
			}
			try {
				String pathOnly = extractPathOnly(requestResponse.getUrl());
				Integer representativeId = findPreviousVisibleRepresentativeIdForPath(pathOnly, requestResponse.getId());
				if (representativeId == null && canRepresentPath(requestResponse)) {
					representativeId = requestResponse.getId();
				}
				updateAutoDuplicateComment(requestResponse, representativeId);
			}
			catch (Exception ignore) {
			}
		}
		fireTableDataChanged();
	}

	public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
		if(listIndex < originalRequestResponseList.size()) {
			return originalRequestResponseList.get(listIndex);
		}
		else {
			return null;
		}
	}
	
	public OriginalRequestResponse getOriginalRequestResponseById(int id) {
		return requestResponseById.get(id);
	}
	
	@Override
	public int getColumnCount() {
		return STATIC_COLUMN_COUNT + (config.getSessions().size()*4);
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseList.size();
	}

	private int sessionCodeStartColumn() {
		return 6;
	}

	private int originalLengthColumn(int sessionCount) {
		return sessionCodeStartColumn() + sessionCount;
	}

	private int sessionLengthStartColumn(int sessionCount) {
		return originalLengthColumn(sessionCount) + 1;
	}

	private int sessionDiffStartColumn(int sessionCount) {
		return sessionLengthStartColumn(sessionCount) + sessionCount;
	}

	private int sessionStatusStartColumn(int sessionCount) {
		return sessionDiffStartColumn(sessionCount) + sessionCount;
	}

	private int commentColumn(int sessionCount) {
		return sessionStatusStartColumn(sessionCount) + sessionCount;
	}

	private AnalyzerRequestResponse getSessionResponse(OriginalRequestResponse originalRequestResponse, int sessionIndex) {
		if (sessionIndex < 0 || sessionIndex >= config.getSessions().size()) {
			return null;
		}
		return config.getSessions().get(sessionIndex).getRequestResponseMap().get(originalRequestResponse.getId());
	}

	@Override
	public Object getValueAt(int row, int column) {
		if(row >= originalRequestResponseList.size()) {
			return null;
		}
		OriginalRequestResponse originalRequestResponse = originalRequestResponseList.get(row);
		if(column == 0) {
			return originalRequestResponse.getId();
		}
		if(column == 1) {
			return  originalRequestResponse.getMethod();
		}
		if(column == 2) {
			return originalRequestResponse.getHost();
		}
		if(column == 3) {
			return originalRequestResponse.getUrl();
		}
		if(column == 4) {
			return originalRequestResponse.getFullUrl();
		}
		if(column == 5) {
			return originalRequestResponse.getStatusCode();
		}
		int sessionCount = config.getSessions().size();
		if(column >= sessionCodeStartColumn() && column < originalLengthColumn(sessionCount)) {
			AnalyzerRequestResponse response = getSessionResponse(originalRequestResponse, column - sessionCodeStartColumn());
			return response == null ? null : response.getStatusCode();
		}
		if(column == originalLengthColumn(sessionCount)) {
			return originalRequestResponse.getResponseContentLength();
		}
		if(column >= sessionLengthStartColumn(sessionCount) && column < sessionDiffStartColumn(sessionCount)) {
			AnalyzerRequestResponse response = getSessionResponse(originalRequestResponse, column - sessionLengthStartColumn(sessionCount));
			return response == null ? null : response.getResponseContentLength();
		}
		if(column >= sessionDiffStartColumn(sessionCount) && column < sessionStatusStartColumn(sessionCount)) {
			AnalyzerRequestResponse response = getSessionResponse(originalRequestResponse, column - sessionDiffStartColumn(sessionCount));
			return response == null ? null : originalRequestResponse.getResponseContentLength() - response.getResponseContentLength();
		}
		if(column >= sessionStatusStartColumn(sessionCount) && column < commentColumn(sessionCount)) {
			AnalyzerRequestResponse response = getSessionResponse(originalRequestResponse, column - sessionStatusStartColumn(sessionCount));
			return response == null ? null : response.getStatus();
		}
		if(column == commentColumn(sessionCount)) {
			return originalRequestResponse.getComment();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public String getColumnName(int column) {
		if(column == 0) {
			return Column.ID.toString();
		}
		if(column == 1) {
			return  Column.Method.toString();
		}
		if(column == 2) {
			return Column.Host.toString();
		}
		if(column == 3) {
			return Column.Path.toString();
		}
		if(column == 4) {
			return Column.FullUrl.toString();
		}
		if(column == 5) {
			return Column.Code.toString();
		}
		int sessionCount = config.getSessions().size();
		if(column >= sessionCodeStartColumn() && column < originalLengthColumn(sessionCount)) {
			return config.getSessions().get(column - sessionCodeStartColumn()).getName() + " " + Column.Code;
		}
		if(column == originalLengthColumn(sessionCount)) {
			return Column.Length.toString();
		}
		if(column >= sessionLengthStartColumn(sessionCount) && column < sessionDiffStartColumn(sessionCount)) {
			return config.getSessions().get(column - sessionLengthStartColumn(sessionCount)).getName() + " " + Column.Length;
		}
		if(column >= sessionDiffStartColumn(sessionCount) && column < sessionStatusStartColumn(sessionCount)) {
			return config.getSessions().get(column - sessionDiffStartColumn(sessionCount)).getName() + " " + Column.Diff;
		}
		if(column >= sessionStatusStartColumn(sessionCount) && column < commentColumn(sessionCount)) {
			return config.getSessions().get(column - sessionStatusStartColumn(sessionCount)).getName() + " " + Column.Status;
		}
		if(column == commentColumn(sessionCount)) {
			return Column.Comment.toString();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if(columnIndex == 0) {
			return Integer.class;
		}
		if(columnIndex == 1) {
			return String.class;
		}
		if(columnIndex == 2) {
			return String.class;
		}
		if(columnIndex == 3) {
			return String.class;
		}
		if(columnIndex == 4) {
			return String.class;
		}
		if(columnIndex == 5) {
			return Integer.class;
		}
		int sessionCount = config.getSessions().size();
		if(columnIndex >= sessionCodeStartColumn() && columnIndex < originalLengthColumn(sessionCount)) {
			return Integer.class;
		}
		if(columnIndex == originalLengthColumn(sessionCount)) {
			return Integer.class;
		}
		if(columnIndex >= sessionLengthStartColumn(sessionCount) && columnIndex < sessionStatusStartColumn(sessionCount)) {
			return Integer.class;
		}
		if(columnIndex >= sessionStatusStartColumn(sessionCount) && columnIndex < commentColumn(sessionCount)) {
			return BypassConstants.class;
		}
		if(columnIndex == commentColumn(sessionCount)) {
			return String.class;
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
	}
	
	public enum Column {
		ID("ID"), Method("方法"), Host("主机"), Path("路径"), FullUrl("完整URL"), Code("状态码"), Length("长度"), Diff("差异"), Status("状态"), Comment("评论");
		
		private final String displayName;
		
		Column(String displayName) {
			this.displayName = displayName;
		}
		
		@Override
		public String toString() {
			return displayName;
		}
		
		public static EnumSet<Column> getDefaultSet() {
			return EnumSet.of(ID, Method, Host, Path, FullUrl, Status);
		}
		
	}
}
