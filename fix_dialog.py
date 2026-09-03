# -*- coding: utf-8 -*-
import io, sys

FILES = [
    r"E:\git\auth_analyzer_modify\src\com\protect7\authanalyzer\gui\main\CenterPanel.java",
    r"E:\auth_analyzer_modify_longfor\src\com\protect7\authanalyzer\gui\main\CenterPanel.java",
]

# 重构后的 showHtmlDialog：跟随当前 LAF 字体/配色（light/dark 主题自适应），全文统一字号，
# 强调词仅用颜色/加粗区分（.em 橙 / .ok 绿 / .warn 红 / .muted 灰），不改变字号。
NEW_METHOD = '''\t/**
\t * 导入流程的提示弹窗。Burp 对 JOptionPane 按纯文本渲染（HTML 标签字面可见），故改用自建模态
\t * JDialog + JEditorPane。字体与配色跟随当前 LAF（与插件其它 UI 一致，light/dark 主题自动适配），
\t * 全文统一字号，强调仅用颜色/加粗区分，不改变字号。
\t *
\t * @param withCancel true 显示"确定/取消"并返回用户选择；false 仅"确定"。
\t */
\tprivate boolean showHtmlDialog(String title, String htmlBody, boolean withCancel) {
\t\tWindow owner = SwingUtilities.getWindowAncestor(this);
\t\tfinal JDialog dialog = new JDialog(owner, title, Dialog.ModalityType.APPLICATION_MODAL);

\t\t// 跟随插件当前 LAF 的字体与配色，保证与其它 UI 一致
\t\tFont uiFont = UIManager.getFont("Label.font");
\t\tString family = uiFont == null ? "SansSerif" : uiFont.getFamily();
\t\tint sizePt = uiFont == null ? 12 : uiFont.getSize();
\t\tColor fg = UIManager.getColor("Label.foreground");
\t\tColor bg = UIManager.getColor("Panel.background");
\t\tif (fg == null) {
\t\t\tfg = Color.BLACK;
\t\t}
\t\tif (bg == null) {
\t\t\tbg = Color.WHITE;
\t\t}

\t\t// 统一样式：全文同一字体/字号；强调词用颜色区分（.em 橙 / .ok 绿 / .warn 红 / .muted 灰）
\t\tString css = "body{font-family:" + family + ";font-size:" + sizePt + "pt;color:#" + hexColor(fg)
\t\t\t\t+ ";background:#" + hexColor(bg) + ";margin:0;width:440px;}"
\t\t\t\t+ ".em{color:#f06e00;}.ok{color:#009900;}.warn{color:#d32f2f;}.muted{color:#888888;}";
\t\tJEditorPane pane = new JEditorPane("text/html",
\t\t\t\t"<html><head><style>" + css + "</style></head><body>" + htmlBody + "</body></html>");
\t\tpane.setEditable(false);
\t\tpane.setOpaque(true);
\t\tpane.setBackground(bg);
\t\tpane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
\t\tpane.setBorder(new EmptyBorder(16, 18, 12, 18));

\t\tfinal boolean[] confirmed = new boolean[1];
\t\tJButton ok = new JButton("确定");
\t\tok.addActionListener(e -> {
\t\t\tconfirmed[0] = true;
\t\t\tdialog.dispose();
\t\t});
\t\tJPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 8));
\t\tbuttons.add(ok);
\t\tif (withCancel) {
\t\t\tJButton cancel = new JButton("取消");
\t\t\tcancel.addActionListener(e -> dialog.dispose());
\t\t\tbuttons.add(cancel);
\t\t}

\t\tJScrollPane scroll = new JScrollPane(pane);
\t\tscroll.setBorder(null);
\t\tscroll.getViewport().setBackground(bg);
\t\tdialog.getContentPane().setLayout(new BorderLayout());
\t\tdialog.getContentPane().add(scroll, BorderLayout.CENTER);
\t\tdialog.getContentPane().add(buttons, BorderLayout.SOUTH);
\t\tdialog.getRootPane().setDefaultButton(ok);
\t\tdialog.pack();
\t\tdialog.setLocationRelativeTo(owner);
\t\tdialog.setVisible(true);
\t\treturn confirmed[0];
\t}

\tprivate static String hexColor(Color color) {
\t\treturn String.format("%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
\t}
'''

# (old, new) 内容级替换：统一字号、统一标签语义
REPLACEMENTS = [
    ("\"<br><font color='red'>⚠ 分析仍在运行：缺失的会话将不会被自动创建，请先停止分析再导入。</font>\"",
     "\"<br><span class='warn'>⚠ 分析仍在运行：缺失的会话将不会被自动创建，请先停止分析再导入。</span>\""),
    ("\"将从备份<strong>覆盖恢复</strong>看板数据（先清空当前看板与所有会话结果）。<br>\"",
     "\"将从备份<span class='em'><b>覆盖恢复</b></span>看板数据（先清空当前看板与所有会话结果）。<br>\""),
    ("\"当前缺失的备份会话将按备份配置<strong>自动创建</strong>（含头替换/Token/匹配替换）。<br>\"",
     "\"当前缺失的备份会话将按备份配置<span class='em'><b>自动创建</b></span>（含头替换/Token/匹配替换）。<br>\""),
    ("\"<font color='gray' size='2'>备份文件: \"",
     "\"<span class='muted'>备份文件: \""),
    ("+ \"</font>\"",
     "+ \"</span>\""),
    ("\"<strong>看板已从备份恢复</strong><br>\"",
     "\"<span class='ok'><b>看板已从备份恢复</b></span><br>\""),
    ("\"<font color='#B06000'>（v1 备份未含会话配置，以上会话为默认空配置，\"",
     "\"<span class='muted'>（v1 备份未含会话配置，以上会话为默认空配置，\""),
    ("\"头替换规则等请自行补充）</font><br>\"",
     "\"头替换规则等请自行补充）</span><br>\""),
    ("\"<br>⚠ 分析运行中，以下备份会话未被自动创建（请停止分析后重新导入）：<br>\"",
     "\"<br><span class='warn'>⚠ 分析运行中，以下备份会话未被自动创建（请停止分析后重新导入）：</span><br>\""),
    ("\"<br>⚠ 以下备份会话无法恢复，其数据已跳过：<br>\"",
     "\"<br><span class='warn'>⚠ 以下备份会话无法恢复，其数据已跳过：</span><br>\""),
]


def replace_method(text, new_method):
    sig = "private boolean showHtmlDialog(String title, String htmlBody, boolean withCancel) {"
    i = text.index(sig)
    j = text.rindex("/**", 0, i)
    k = text.index("return confirmed[0];", i)
    end = text.index("\n\t}", k) + len("\n\t}")
    return text[:j] + new_method + text[end:]


for path in FILES:
    raw = io.open(path, encoding="utf-8", newline="").read()
    had_crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    # imports: Dimension -> Font（原本未被使用）；新增 UIManager
    assert "import java.awt.Dimension;\n" in text, "Dimension import missing: " + path
    text = text.replace("import java.awt.Dimension;\n", "import java.awt.Font;\n", 1)
    assert "import javax.swing.Timer;\n" in text, "Timer import missing: " + path
    text = text.replace("import javax.swing.Timer;\n",
                        "import javax.swing.Timer;\nimport javax.swing.UIManager;\n", 1)

    # 重写 showHtmlDialog 方法（含前置注释块）
    text = replace_method(text, NEW_METHOD)

    # 统一标签语义
    for old, new in REPLACEMENTS:
        c = text.count(old)
        if c != 1:
            print("FAIL [%s] count=%d for: %r" % (path, c, old[:70]))
            sys.exit(1)
        text = text.replace(old, new, 1)

    out = text.replace("\n", "\r\n") if had_crlf else text
    io.open(path, "w", encoding="utf-8", newline="").write(out)
    print("OK", path, "crlf=", had_crlf)

print("ALL DONE")
