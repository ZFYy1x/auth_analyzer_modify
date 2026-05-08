package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.MenuSelectionManager;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.RowSorterListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.dialog.DataExportDialog;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.CustomRowSorter;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.montoya.HttpExchange;
import burp.BurpExtender;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

public class CenterPanel extends JPanel {

	private static final long serialVersionUID = 8472627619821851125L;
	private final MainPanel mainPanel;
	private final String TABLE_SETTINGS = "TABLE_SETTINGS";
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final ImageIcon loaderImageIcon = new ImageIcon(this.getClass().getClassLoader().getResource("loader.gif"));
	private final JTable table;
	private final JPanel tablePanel = new JPanel(new BorderLayout());
	private final ListSelectionModel selectionModel;
	private final HashSet<Column> columnSet = new HashSet<Column>();
	private RequestTableModel tableModel;
	private final JPanel messageViewPanel;
	private CustomRowSorter sorter;
	private final RequestResponsePanel tabbedPanel1;
	private final JSplitPane splitPane;
	private final JButton clearTableButton;
	private final JCheckBox showOnlyMarked = new JCheckBox("已标记", false);
	private final JCheckBox showDuplicates = new JCheckBox("去除重复(多维)", true);
	private final JCheckBox showBypassed = new JCheckBox("状态 " + BypassConstants.SAME.getName(), true);
	private final JCheckBox showPotentialBypassed = new JCheckBox("状态 " + BypassConstants.SIMILAR.getName(), true);
	private final JCheckBox showNotBypassed = new JCheckBox("状态 " + BypassConstants.DIFFERENT.getName(), true);
	private final JCheckBox showNA = new JCheckBox("状态 " + BypassConstants.NA.getName(), true);
	private final PlaceholderTextField filterText;
	private final JPanel topPanel = new JPanel(new BorderLayout());
	private final JLabel tableFilterInfoLabel = new JLabel("", SwingConstants.CENTER);
	private final JLabel pendingRequestsLabel = new JLabel("", SwingConstants.CENTER);
	private final JCheckBox searchInPath = new JCheckBox("在路径中搜索", true);
	private final JCheckBox searchInRequest = new JCheckBox("在请求中搜索", false);
	private final JCheckBox searchInResponse = new JCheckBox("在响应中搜索", false);
	private final JCheckBox negativeSearch = new JCheckBox("反向搜索", false);
	private final JButton searchButton = new JButton("搜索");
	private int selectedId = -1;
	// 合并高频变更导致的排序/重绘，降低大批量数据时的卡顿
	private Timer sortDebounceTimer;
	private Timer pendingRequestsUiTimer;
	private final AtomicInteger pendingRequestsUiValue = new AtomicInteger(0);
	private final AtomicBoolean pendingRequestsUiUpdateQueued = new AtomicBoolean(false);

	public CenterPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());
		table = new JTable();
		// 初始化排序防抖定时器，需在 table 初始化后使用
		sortDebounceTimer = new Timer(120, e -> {
			updateTableFilterInfo();
			table.revalidate();
			table.repaint();
		});
		sortDebounceTimer.setRepeats(false);
		tablePanel.setBorder(BorderFactory.createLineBorder(Color.gray));
		JPanel tableControlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 30, 5));
		JButton filterButton = new JButton();
		filterButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("filter.png")));
		filterButton.addActionListener(e -> showTableFilterDialog(tableControlPanel));
		filterText = new PlaceholderTextField(20);
		filterText.setPlaceholder("输入搜索模式...");
		searchButton.addActionListener(e -> {
			searchButton.setEnabled(false);
			try {
				if (sorter != null) {
					sorter.rebuildIndex();
				}
				tableModel.fireTableDataChanged();
				if (sorter != null) {
					sorter.sort();
				}
			} catch (Exception ignore) {}
			finally {
				searchButton.setEnabled(true);
			}
		});
		showDuplicates.setToolTipText("勾选：隐藏重复请求（多维签名）；取消勾选：显示所有，包括重复");
		JPanel searchPanel = new JPanel();
		searchPanel.add(filterText);
		searchPanel.add(searchButton);
		tableControlPanel.add(searchPanel);
		tableControlPanel.add(filterButton);
		JButton settingsButton = new JButton();
		settingsButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("settings.png")));
		settingsButton.addActionListener(e -> showTableSettingsDialog(tableControlPanel));
		tableControlPanel.add(settingsButton);
		topPanel.add(tableControlPanel, BorderLayout.NORTH);
		tableFilterInfoLabel.putClientProperty("html.disable", null);
		topPanel.add(tableFilterInfoLabel, BorderLayout.CENTER);
		pendingRequestsLabel.setForeground(new Color(240, 110, 0));
		pendingRequestsLabel.setVisible(false);
		topPanel.add(pendingRequestsLabel, BorderLayout.SOUTH);
		
		tablePanel.add(new JScrollPane(topPanel, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.NORTH);
	
		loadTableSettings();
		initTableWithModel();		
		table.setDefaultRenderer(Integer.class, new BypassCellRenderer());
		table.setDefaultRenderer(String.class, new BypassCellRenderer());
		table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());	
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
		
		JPanel tableConfigPanel = new JPanel();
		clearTableButton = new JButton("清除表格");
		clearTableButton.addActionListener(e -> clearTablePressed());
		tableConfigPanel.add(clearTableButton);
		JButton exportDataButton = new JButton("导出表格数据");
		exportDataButton.addActionListener(e -> { 
			exportDataButton.setIcon(loaderImageIcon);
			exportDataButton.setEnabled(false);
			
			// 使用CompletableFuture进行异步导出
			CompletableFuture.runAsync(() -> {
				new DataExportDialog(CenterPanel.this);
			}).thenRun(() -> {
				// 在EDT线程中恢复按钮状态
				SwingUtilities.invokeLater(() -> {
					exportDataButton.setIcon(null);
					exportDataButton.setEnabled(true);
				});
			}).exceptionally(throwable -> {
				// 处理异常
				SwingUtilities.invokeLater(() -> {
					exportDataButton.setIcon(null);
					exportDataButton.setEnabled(true);
					// 可以显示错误消息
				});
				return null;
			});
		});
		tableConfigPanel.add(exportDataButton);
		
		JButton copyUrlsButton = new JButton("去重复制URL");
		copyUrlsButton.addActionListener(e -> copyUrlsToClipboard());
		tableConfigPanel.add(copyUrlsButton);
		tablePanel.add(tableConfigPanel, BorderLayout.SOUTH);
		
		tabbedPanel1 = new RequestResponsePanel(0, this);
		messageViewPanel = new JPanel(new BorderLayout());
		messageViewPanel.add(tabbedPanel1, BorderLayout.CENTER);
		
		messageViewPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tabbedPanel1.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, messageViewPanel);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);

		selectionModel = table.getSelectionModel();
		// 允许 Ctrl/Command 非连续多选，避免只能 Shift 连续选择
		selectionModel.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) { 
				changeRequestResponseView(false);
			}
			
		});
		setupTableContextMenu();
	}

	private void loadTableSettings() {
		String savedSettings = BurpExtender.api.persistence().preferences().getString(TABLE_SETTINGS);
		if (savedSettings != null) {
			String[] split = savedSettings.split(",");
			for (String columnAsString : split) {
				for (Column column : Column.values()) {
					if (columnAsString.equals(column.toString())) {
						columnSet.add(column);
					}
				}
			}
		} else {
			for (Column column : Column.getDefaultSet()) {
				columnSet.add(column);
			}
		}
	}

	public void updateOtherTabbedPane(int tabbedPaneId, int index) {
		// Single message view only.
	}

	public void updateDiffPane() {
		// Diff view has been removed.
	}

	private void setupTableContextMenu() {
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.getButton() == MouseEvent.BUTTON3) {
					int[] rows = table.getSelectedRows();
					if (rows.length > 0) {
						JPopupMenu contextMenu = new JPopupMenu();
						// Ensure the popup is dismissed before executing any action.
						// Some actions (e.g. sending to Repeater / opening dialogs) can otherwise leave
						// a "stuck" popup UI on top of the table.
						final Runnable hideContextMenu = () -> {
							try {
								contextMenu.setVisible(false);
							} catch (Exception ignore) {}
							try {
								MenuSelectionManager.defaultManager().clearSelectedPath();
							} catch (Exception ignore) {}
						};
						final ArrayList<OriginalRequestResponse> requestResponseList = new ArrayList<OriginalRequestResponse>();
						String appendix = "";
						if (rows.length > 1) {
							appendix = "s";
						}
						for (int row : rows) {
							requestResponseList
									.add(tableModel.getOriginalRequestResponse(table.convertRowIndexToModel(row)));
						}
						JMenuItem unmarkRowItem = new JMenuItem("取消标记行" + appendix);
						unmarkRowItem.addActionListener(e -> {
							hideContextMenu.run();
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(false);
							}
						});
						JMenuItem markRowItem = new JMenuItem("标记行" + appendix);
						markRowItem.addActionListener(e -> {
							hideContextMenu.run();
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(true);
							}
						});
						JMenuItem repeatRequestItem = new JMenuItem("重复请求" + appendix);
						repeatRequestItem.addActionListener(e -> {
							hideContextMenu.run();
							Collections.sort(requestResponseList);
							HttpExchange[] messages = new HttpExchange[requestResponseList.size()];
							for (int i=0; i<requestResponseList.size(); i++) {
								messages[i] = requestResponseList.get(i).getRequestResponse();
							}
							GenericHelper.repeatRequests(messages, mainPanel.getConfigurationPanel());
						});
						JMenuItem deleteRowItem = new JMenuItem("删除行" + appendix);
						deleteRowItem.addActionListener(e -> {
						hideContextMenu.run();
						for (OriginalRequestResponse requestResponse : requestResponseList) {
							tableModel.deleteRequestResponse(requestResponse);
						}
						// 删除后确保排序/过滤与UI同步
						SwingUtilities.invokeLater(new Runnable() {
							@Override
							public void run() {
								try {
									if (sorter != null) {
										sorter.sort();
									}
								} catch (Exception ignore) {}
								// 若无选中项，重置右侧详情面板，避免显示已删除对象
								if (table.getSelectedRowCount() == 0) {
									selectedId = -1;
									messageViewPanel.revalidate();
								}
								table.revalidate();
								table.repaint();
							}
						});
						});
						
						// 发送到 Repeater 的子菜单（支持批量、带标签、自定义标签）
						JMenu sendToRepeaterMenu = new JMenu("发送到 Repeater" + appendix);
						String[] repeaterTags = new String[] {"水平越权", "垂直越权", "未授权", "水平垂直", "水平垂直未授权"};
						for (String tag : repeaterTags) {
							JMenuItem sendWithTagItem = new JMenuItem(tag);
							sendWithTagItem.addActionListener(e -> {
								hideContextMenu.run();
								// Offload to background thread to keep EDT responsive and avoid popup "sticking".
								CompletableFuture.runAsync(() -> sendToRepeater(requestResponseList, tag));
							});
							sendToRepeaterMenu.add(sendWithTagItem);
						}
						JMenuItem sendCustomItem = new JMenuItem("自定义");
						sendCustomItem.addActionListener(e -> {
							hideContextMenu.run();
							// Show dialog on EDT after the popup is dismissed.
							SwingUtilities.invokeLater(() -> sendWithCustomTag(requestResponseList));
						});
						sendToRepeaterMenu.addSeparator();
						sendToRepeaterMenu.add(sendCustomItem);

						JMenuItem commentItem = new JMenuItem("评论");
						commentItem.addActionListener(e -> {
							hideContextMenu.run();
							if (requestResponseList.size() > 0) {
								JTextArea commentTextArea = new JTextArea(requestResponseList.get(0).getComment(), 2,
										8);
								JOptionPane.showMessageDialog(commentItem, new JScrollPane(commentTextArea), "评论",
										JOptionPane.INFORMATION_MESSAGE);
								for (OriginalRequestResponse requestResponse : requestResponseList) {
									requestResponse.setComment(commentTextArea.getText());
								}
							}
						});
						if (rows.length == 1) {
							if (requestResponseList.get(0).isMarked()) {
								contextMenu.add(unmarkRowItem);
							} else {
								contextMenu.add(markRowItem);
							}
						} else {
							contextMenu.add(markRowItem);
							contextMenu.add(unmarkRowItem);
						}
						contextMenu.add(repeatRequestItem);
						contextMenu.add(deleteRowItem);
						contextMenu.add(sendToRepeaterMenu);
						contextMenu.add(commentItem);
						contextMenu.show(event.getComponent(), event.getX(), event.getY());
					}
				}
			}
		});
	}
	
	// 批量发送到 Repeater，并给 tab 命名（带标签区分）
	private void sendToRepeater(ArrayList<OriginalRequestResponse> requestResponseList, String tag) {
		for (int i = 0; i < requestResponseList.size(); i++) {
			OriginalRequestResponse orr = requestResponseList.get(i);
			if (orr == null || orr.getRequestResponse() == null) {
				continue;
			}
			try {
				HttpExchange ihrr = orr.getRequestResponse();
				if (ihrr.getHttpService() == null || ihrr.getRequest() == null) {
					continue;
				}
				String tabName = tag;
				// 批量时保证唯一性，便于在 Repeater 中区分；带标签名称模拟“分组”
				if (requestResponseList.size() > 1) {
					tabName = tag + "-" + orr.getId();
				}
				BurpExtender.api.repeater().sendToRepeater(ihrr.getRequest(), tabName);
			} catch (Exception ignore) {}
		}
	}
	
	// 弹出自定义标签输入框并发送
	private void sendWithCustomTag(ArrayList<OriginalRequestResponse> requestResponseList) {
		// Defensive: make sure any menu selection/popup is cleared before showing dialogs.
		try {
			MenuSelectionManager.defaultManager().clearSelectedPath();
		} catch (Exception ignore) {}
		String customTag = JOptionPane.showInputDialog(this, "请输入自定义标签名称:", "发送到 Repeater - 自定义标签", JOptionPane.PLAIN_MESSAGE);
		if (customTag != null) {
			customTag = customTag.trim();
		}
		if (customTag == null || customTag.isEmpty()) {
			return; // 取消或空输入，不发送
		}
		sendToRepeater(requestResponseList, customTag);
	}

	// Paint center panel according to session list
	public void initCenterPanel() {
		initTableWithModel();
		tabbedPanel1.init();
		selectedId = -1;
		splitPane.setResizeWeight(0.5d);
	}

	public void clearTablePressed() {
		clearTableButton.setIcon(loaderImageIcon);
		clearTableButton.setEnabled(false);
		
		// 使用CompletableFuture进行异步清除
		CompletableFuture.runAsync(() -> {
			clearTable();
		}).thenRun(() -> {
			// 在EDT线程中恢复按钮状态
			SwingUtilities.invokeLater(() -> {
				clearTableButton.setIcon(null);
				clearTableButton.setEnabled(true);
			});
		}).exceptionally(throwable -> {
			// 处理异常
			SwingUtilities.invokeLater(() -> {
				clearTableButton.setIcon(null);
				clearTableButton.setEnabled(true);
			});
			return null;
		});
	}

	public void clearTable() {
		config.clearSessionRequestMaps();
		if (sorter != null) {
			sorter.clearIndex();
		}
		tableModel.clearRequestMap();
		selectedId = -1;
	}

	public ArrayList<OriginalRequestResponse> getFilteredRequestResponseList() {
		ArrayList<OriginalRequestResponse> list = new ArrayList<OriginalRequestResponse>();
		for (int row = 0; row < table.getRowCount(); row++) {
			OriginalRequestResponse requestResponse = tableModel
					.getOriginalRequestResponse(table.convertRowIndexToModel(row));
			list.add(requestResponse);
		}
		return list;
	}
	
	public void toggleSearchButtonText() {
		if(searchButton.getIcon() == null) {
			searchButton.setIcon(loaderImageIcon);
		}
		else {
			searchButton.setIcon(null);
		}
	}

	private void initTableWithModel() {
		tableModel = new RequestTableModel();
		table.setModel(tableModel);
		config.setTableModel(tableModel);
		sorter = new CustomRowSorter(this, tableModel, showOnlyMarked, showDuplicates, showBypassed, 
				showPotentialBypassed, showNotBypassed, showNA, filterText, searchInPath, searchInRequest, searchInResponse, negativeSearch);
		sorter.addRowSorterListener(new RowSorterListener() {
			@Override
			public void sorterChanged(RowSorterEvent e) {
				updateTableFilterInfo();
			}
		});
        table.setRowSorter(sorter);
        // Ensure view refreshes promptly after model changes to avoid delayed repaint until hover
        tableModel.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
				Runnable r = () -> sortDebounceTimer.restart();
				if (SwingUtilities.isEventDispatchThread()) {
					r.run();
				} else {
					SwingUtilities.invokeLater(r);
				}
            }
        });
        updateColumnWidths();
	}

	private void updateTableFilterInfo() {
		if(table.getRowCount() < tableModel.getRowCount()) {
			String text = "<html><h3 style='color:red;'>表格已过滤: " + table.getRowCount() + "/"+
					tableModel.getRowCount()+" 可见条目...</h3></html>";
			tableFilterInfoLabel.setText(text);
			tableFilterInfoLabel.setVisible(true);
		}
		else {
			tableFilterInfoLabel.setVisible(false);
		}
		tablePanel.revalidate();
	}
	
	public void updateAmountOfPendingRequests(int amountOfPendingRequests) {
		pendingRequestsUiValue.set(amountOfPendingRequests);
		if (!pendingRequestsUiUpdateQueued.compareAndSet(false, true)) {
			return;
		}
		SwingUtilities.invokeLater(() -> {
			if (pendingRequestsUiTimer == null) {
				pendingRequestsUiTimer = new Timer(300, e -> {
					pendingRequestsUiUpdateQueued.set(false);
					flushPendingRequestsUi();
				});
				pendingRequestsUiTimer.setRepeats(false);
			}
			if (!pendingRequestsUiTimer.isRunning()) {
				pendingRequestsUiTimer.start();
			} else {
				pendingRequestsUiUpdateQueued.set(false);
			}
		});
	} 

	private void flushPendingRequestsUi() {
		int pending = pendingRequestsUiValue.get();
		if(pending == 0) {
			pendingRequestsLabel.setVisible(false);
		}
		else {
			pendingRequestsLabel.setVisible(true);
			pendingRequestsLabel.setText("待处理请求队列: " + pending);
		}
	}
	
	private void changeRequestResponseView(boolean force) {
		if (table.getSelectedRow() != -1) {
			int modelRowIndex = table.convertRowIndexToModel(table.getSelectedRow());
			OriginalRequestResponse originalRequestResponse = tableModel.getOriginalRequestResponse(modelRowIndex);
			if (force || (originalRequestResponse != null && selectedId != originalRequestResponse.getId())) {
				selectedId = originalRequestResponse.getId();
				HttpExchange originalExchange = originalRequestResponse.getRequestResponse();
				HttpRequestEditor requestMessageEditorOriginal = createRequestEditor(originalExchange.getRequest());
				tabbedPanel1.setRequestMessage(tabbedPanel1.TITLE_ORIGINAL, requestMessageEditorOriginal.uiComponent(),
						() -> requestMessageEditorOriginal.getRequest().toString());
				if (originalExchange.getResponse() != null) {
					HttpResponseEditor responseMessageEditorOriginal = createResponseEditor(originalExchange.getResponse());
					tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
							responseMessageEditorOriginal.uiComponent(),
							() -> responseMessageEditorOriginal.getResponse().toString());
				} else {
					tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
						getMessageViewLabel(originalRequestResponse.getInfoText()), null);
				}

				for (Session session : config.getSessions()) {
					AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap()
							.get(originalRequestResponse.getId());
					HttpExchange sessionRequestResponse = analyzerRequestResponse.getRequestResponse();
					if (sessionRequestResponse != null) {
						HttpRequestEditor requestMessageEditor = createRequestEditor(sessionRequestResponse.getRequest());
						tabbedPanel1.setRequestMessage(session.getName(), requestMessageEditor.uiComponent(),
								() -> requestMessageEditor.getRequest().toString());

						if (sessionRequestResponse.getResponse() != null) {
							HttpResponseEditor responseMessageEditor = createResponseEditor(sessionRequestResponse.getResponse());
							tabbedPanel1.setResponseMessage(session.getName(), responseMessageEditor.uiComponent(),
									() -> responseMessageEditor.getResponse().toString());
						}
					} else {
						tabbedPanel1.setRequestMessage(session.getName(),
								getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
						tabbedPanel1.setResponseMessage(session.getName(),
								getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
					}
				}
				SwingUtilities.invokeLater(new Runnable() {

					@Override
					public void run() {
						messageViewPanel.revalidate();
					}
				});
			}
		}
	}

	private HttpRequestEditor createRequestEditor(HttpRequest request) {
		HttpRequestEditor editor = BurpExtender.api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
		editor.setRequest(request);
		return editor;
	}

	private HttpResponseEditor createResponseEditor(HttpResponse response) {
		HttpResponseEditor editor = BurpExtender.api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
		editor.setResponse(response);
		return editor;
	}

	private JLabel getMessageViewLabel(String text) {
		String labelText = "";
		if (text != null) {
			labelText = text;
		}
		return new JLabel(labelText, JLabel.CENTER);
	}

	private void updateColumnWidths() {		
		for (Column column : Column.values()) {
			if (!columnSet.contains(column)) {
				for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
					String columnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
					if(columnName.endsWith(column.toString())) {
						table.getColumnModel().getColumn(i).setMinWidth(0);
						table.getColumnModel().getColumn(i).setMaxWidth(0);
					}
				}
			} else {
				if (column == Column.ID) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setMaxWidth(40);
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setPreferredWidth(40);
				} else if (column == Column.Host) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setPreferredWidth(200);
				} else if (column == Column.Path) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setPreferredWidth(400);
				} else if (column == Column.FullUrl) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.FullUrl)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.FullUrl)).setPreferredWidth(600);
				} else {
					for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
						String currentColumnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
						if(currentColumnName.endsWith(column.toString())) {
							table.getColumnModel().getColumn(i).setMaxWidth(10000);
							table.getColumnModel().getColumn(i).setPreferredWidth(80);
						}
					}
				}
			}
		}
	}
	
	private int getColumnIdByName(Column columnName) {
		for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
			String currentColumnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
			if(currentColumnName.endsWith(columnName.toString())) {
				return i;
			}
		}
		return -1;
	}
	
	private void showTableFilterDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		inputPanel.add(new JLabel("表格过滤"));
		inputPanel.add(showOnlyMarked);
		inputPanel.add(showDuplicates);
		inputPanel.add(showBypassed);
		inputPanel.add(showPotentialBypassed);
		inputPanel.add(showNotBypassed);
		inputPanel.add(showNA);
		
		inputPanel.add(new JLabel(" "));
		inputPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
		inputPanel.add(new JLabel(" "));
		inputPanel.add(new JLabel("搜索选项"));
		inputPanel.add(searchInPath);
		inputPanel.add(searchInRequest);
		inputPanel.add(searchInResponse);	
		inputPanel.add(negativeSearch);
		JOptionPane.showConfirmDialog(parent, inputPanel, "表格过滤", JOptionPane.CLOSED_OPTION);
		// 对话框关闭后，立即刷新过滤结果
		try {
			tableModel.fireTableDataChanged();
			if (sorter != null) {
				sorter.sort();
			}
			table.revalidate();
			table.repaint();
		} catch (Exception ignore) {}
		
	}
	
	private void showTableSettingsDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		inputPanel.add(new JLabel("显示列"));
		for (Column column : Column.values()) {
			JCheckBox columnCheckBox = new JCheckBox(column.toString());
			columnCheckBox.setSelected(columnSet.contains(column));
			columnCheckBox.addActionListener(e -> {
				if (columnCheckBox.isSelected()) {
					columnSet.add(column);
				} else {
					columnSet.remove(column);
				}
				updateColumnWidths();
			});
			inputPanel.add(columnCheckBox);
		}
		JOptionPane.showConfirmDialog(parent, inputPanel, "显示/隐藏列", JOptionPane.CLOSED_OPTION);
		String saveString = columnSet.toString().replaceAll(" ", "").replace("[", "").replace("]", "");
		BurpExtender.api.persistence().preferences().setString(TABLE_SETTINGS, saveString);
	}

	private void copyUrlsToClipboard() {
		try {
			// 获取表格模型
			if (tableModel == null || tableModel.getRowCount() == 0) {
				JOptionPane.showMessageDialog(this, "没有可复制的数据。", "无数据", JOptionPane.WARNING_MESSAGE);
				return;
			}
			
			// 仅复制当前可见（过滤/排序后）行的 FullUrl
			java.util.LinkedHashSet<String> uniqueFullUrls = new java.util.LinkedHashSet<String>();
			for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
				int modelRow = table.convertRowIndexToModel(viewRow);
				Object fullUrlValue = tableModel.getValueAt(modelRow, 4);
				if (fullUrlValue != null) {
					String fullUrl = fullUrlValue.toString();
					if (!fullUrl.trim().isEmpty()) {
						uniqueFullUrls.add(fullUrl);
					}
				}
			}
			
			if (!uniqueFullUrls.isEmpty()) {
				// 复制到剪贴板
				String fullUrls = String.join(System.lineSeparator(), uniqueFullUrls);
				java.awt.datatransfer.StringSelection stringSelection = new java.awt.datatransfer.StringSelection(fullUrls);
				java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
				clipboard.setContents(stringSelection, stringSelection);
				
				JOptionPane.showMessageDialog(this, 
					"成功去重复制 " + uniqueFullUrls.size() + " 个完整URL到剪贴板！", 
					"复制成功", 
					JOptionPane.INFORMATION_MESSAGE);
			} else {
				JOptionPane.showMessageDialog(this, "未找到可复制的完整URL。", "未找到URL", JOptionPane.WARNING_MESSAGE);
			}
		} catch (Exception e) {
			JOptionPane.showMessageDialog(this, 
				"复制完整URL时出错: " + e.getMessage(), 
				"复制错误", 
				JOptionPane.ERROR_MESSAGE);
			e.printStackTrace();
		}
	}
}
