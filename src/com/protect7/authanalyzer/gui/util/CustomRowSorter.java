package com.protect7.authanalyzer.gui.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableRowSorter;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	// 搜索索引缓存
	private final Map<Integer, String> requestContentCache = new HashMap<Integer, String>();
	private final Map<Integer, String> responseContentCache = new HashMap<Integer, String>();
	private volatile boolean indexBuilt = false;
	
	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch) {
		super(tableModel);
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNA.addActionListener(e -> tableModel.fireTableDataChanged());
		filterText.addActionListener(e -> tableModel.fireTableDataChanged());
		setMaxSortKeys(1);
		setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		// 避免每次数据更新都自动重新排序，降低大数据量时的卡顿
		setSortsOnUpdates(false);
		
		// 构建搜索索引
		buildSearchIndex();
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				if(filterText.getText() != null && !filterText.getText().equals("")) {
					boolean doShow = false;
					if(searchInPath.isSelected()) {
						boolean contained = entry.getStringValue(3).toString().contains(filterText.getText());
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							String requestContent = requestContentCache.get(id);
							if (requestContent != null) {
								boolean contained = requestContent.contains(filterText.getText());
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
									doShow = true;
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(searchInResponse.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							String responseContent = responseContentCache.get(id);
							if (responseContent != null) {
								boolean contained = responseContent.contains(filterText.getText());
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
									doShow = true;
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(!doShow && (searchInPath.isSelected() || searchInResponse.isSelected() || searchInRequest.isSelected())) {
						return false;
					}
				}
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				// 勾选时启用去重过滤；未勾选时不过滤重复项
				if(showDuplicates.isSelected()) {
					int id = Integer.parseInt(entry.getStringValue(0));
					String method = entry.getStringValue(1);
					String host = entry.getStringValue(2);
					String fullUrl = entry.getStringValue(4);
					byte[] requestBytes = null;
					try {
						OriginalRequestResponse orr = tableModel.getOriginalRequestResponseById(id);
						if (orr != null && orr.getRequestResponse() != null) {
							requestBytes = orr.getRequestResponse().getRequest();
						}
					}
					catch (Exception ex) {}
					// 折叠相同请求；非GET包含请求体签名
					if(tableModel.isDuplicateByRequestSignature(id, method, host, fullUrl, requestBytes)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SAME.toString())) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SIMILAR.toString())) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.DIFFERENT.toString())) {
							return true;
						}
					}
				}
				if(showNA.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.NA.toString())) {
							return true;
						}
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
	}
	
	/**
	 * 构建搜索索引，缓存请求和响应内容
	 */
	private void buildSearchIndex() {
		if (indexBuilt) {
			return;
		}
		
		try {
			for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
				for (Map.Entry<Integer, AnalyzerRequestResponse> entry : session.getRequestResponseMap().entrySet()) {
					int id = entry.getKey();
					AnalyzerRequestResponse arr = entry.getValue();
					
					// 缓存请求内容
					if (arr.getRequestResponse() != null && arr.getRequestResponse().getRequest() != null) {
						if (!requestContentCache.containsKey(id)) {
							requestContentCache.put(id, new String(arr.getRequestResponse().getRequest()));
						}
					}
					
					// 缓存响应内容
					if (arr.getRequestResponse() != null && arr.getRequestResponse().getResponse() != null) {
						if (!responseContentCache.containsKey(id)) {
							responseContentCache.put(id, new String(arr.getRequestResponse().getResponse()));
						}
					}
				}
			}
			indexBuilt = true;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 清理索引缓存
	 */
	public void clearIndex() {
		requestContentCache.clear();
		responseContentCache.clear();
		indexBuilt = false;
	}
	
	/**
	 * 重建索引
	 */
	public void rebuildIndex() {
		clearIndex();
		buildSearchIndex();
	}
}
