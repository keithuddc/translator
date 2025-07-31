import os
import json
import requests
import urllib3
import time
from datetime import datetime, timezone
import hashlib
import hmac
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sys
import re
import threading

urllib3.disable_warnings()

# === 修复中文输入乱码问题 ===
def fix_input_encoding(text):
    try:
        return text.encode("utf-8").decode("utf-8")
    except UnicodeDecodeError:
        return text.encode("utf-8").decode("gbk")

# === 1️⃣ 加载 config.json（现在由用户主动配置）===
config_data = {"secret_id": "", "secret_key": "", "file_mapping": {}}
config_file_path = 'config.json'

def load_config():
    global config_data
    if not os.path.exists(config_file_path):
        raise FileNotFoundError("❌ 配置文件不存在，请先配置")
    
    with open(config_file_path, 'r', encoding='utf-8') as f:
        try:
            config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"❌ config.json 格式错误：{e}")

def save_config():
    global config_data
    if not all([config_data["secret_id"], config_data["secret_key"], config_data["file_mapping"]]):
        messagebox.showwarning("⚠️ 配置未完成", "请填写所有字段后再保存！")
        return False
    
    with open(config_file_path, 'w', encoding='utf-8') as f:
        json.dump(config_data, f, indent=4, ensure_ascii=False)
    messagebox.showinfo("✅ 保存成功", "配置已保存至 config.json")
    return True

# === 2️⃣ 获取版本信息（修复打包后版本号问题）===
def get_version_from_resource():
    try:
        # 首先尝试从打包后的资源目录获取
        if getattr(sys, 'frozen', False):
            # 打包后的可执行文件路径
            exe_dir = os.path.dirname(sys.executable)
            
            # 尝试在可执行文件目录查找
            version_path = os.path.join(exe_dir, "version.json")
            if os.path.exists(version_path):
                with open(version_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            
            # 尝试在资源目录查找
            bundle_dir = sys._MEIPASS
            version_path = os.path.join(bundle_dir, "version.json")
            if os.path.exists(version_path):
                with open(version_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            
            # 尝试在当前工作目录查找
            version_path = os.path.join(os.getcwd(), "version.json")
            if os.path.exists(version_path):
                with open(version_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            
            raise FileNotFoundError("version.json not found in any location")
        
        # 正常脚本运行时
        bundle_dir = os.path.dirname(os.path.abspath(__file__))
        version_path = os.path.join(bundle_dir, "version.json")
        if not os.path.exists(version_path):
            raise FileNotFoundError("version.json not found in script directory")
        
        with open(version_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ 无法读取版本信息：{e}")
        return {"version": "0.0.0", "changelog": "无法获取更新日志", "download_url": ""}

# === 3️⃣ 腾讯云翻译 API（使用 config.json 中的密钥）===
def get_translation(text, target, secret_id, secret_key):
    service = "tmt"
    host = "tmt.tencentcloudapi.com"
    region = "ap-beijing"
    version = "2018-03-21"
    action = "TextTranslate"
    endpoint = "https://tmt.tencentcloudapi.com"
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    payload = "{\"SourceText\":\"%s\",\"Source\":\"auto\",\"Target\":\"%s\",\"ProjectId\":0}" % (text, target)
    params = json.loads(payload)
    http_request_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json; charset=utf-8"
    canonical_headers = "content-type:%s\nhost:%s\nx-tc-action:%s\n" % (ct, host, action.lower())
    signed_headers = "content-type;host;x-tc-action"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (http_request_method + "\n" +
                         canonical_uri + "\n" +
                         canonical_querystring + "\n" +
                         canonical_headers + "\n" +
                         signed_headers + "\n" +
                         hashed_request_payload)
    credential_scope = date + "/" + service + "/" + "tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = (algorithm + "\n" +
                     str(timestamp) + "\n" +
                     credential_scope + "\n" +
                     hashed_canonical_request)
    secret_date = hmac.new(("TC3" + secret_key).encode("utf-8"), date.encode("utf-8"), hashlib.sha256).digest()
    secret_service = hmac.new(secret_date, service.encode("utf-8"), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, "tc3_request".encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (algorithm + " " +
                     "Credential=" + secret_id + "/" + credential_scope + ", " +
                     "SignedHeaders=" + signed_headers + ", " +
                     "Signature=" + signature)
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version
    }
    if region:
        headers["X-TC-Region"] = region
    resp = requests.post(endpoint, headers=headers, data=payload.encode("utf-8"), verify=False)
    result = json.loads(resp.text)
    if "Response" in result and "TargetText" in result["Response"]:
        return result["Response"]["TargetText"]
    else:
        raise Exception(f"翻译失败: {result}")

# === 4️⃣ 文件路径处理（支持相对路径）===
def resolve_path(path):
    if os.path.isabs(path):
        return path
    else:
        return os.path.abspath(path)

# ✅ 全局变量：记录是否已经确认过 key 是否存在（避免重复弹窗）
_key_confirmation = {}

def insert_key_value_at_line(filename, key, value, line_number=0, space_count=0, separator="", key_space_count=1, value_wrapper="\""):
    try:
        line_number = int(line_number)
        space_count = int(space_count)
        key_space_count = int(key_space_count)
    except (ValueError, TypeError):
        raise ValueError(f"line_number、space_count、key_space_count 必须是整数，当前值: {line_number}（类型: {type(line_number)}），{space_count}（类型: {type(space_count)}），{key_space_count}（类型: {type(key_space_count)}）")

    if not os.path.exists(filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            f.write("")

    with open(filename, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if line_number == 0:
        line_index = len(lines)
    else:
        line_index = len(lines) - line_number + 1
        if line_index < 0:
            line_index = 0

    indent = " " * space_count
    wrapper = value_wrapper.strip()

    # 如果包裹符号为空，则不添加任何包裹
    if wrapper == "":
        key_wrapped = key
        value_wrapped = value
    else:
        key_wrapped = f"{wrapper}{key}{wrapper}"
        value_wrapped = f"{wrapper}{value}{wrapper}"

    key_exists = any(line.strip().startswith(key_wrapped + ":") for line in lines)

    if key_exists:
        if key not in _key_confirmation:
            result = messagebox.askyesno(
                "⚠️ Key 已存在",
                f"文件中已存在 key：'{key}'\n是否继续写入？"
            )
            _key_confirmation[key] = result
        if not _key_confirmation[key]:
            log_text.insert(tk.END, f"🚫 中断执行：用户取消写入 {key}\n")
            return

    new_line = f"{indent}{key_wrapped}:{' ' * key_space_count}{value_wrapped}{separator}\n"
    lines.insert(line_index, new_line)

    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(lines)

# === 5️⃣ 配置弹窗（主界面左上角按钮触发）===
def open_config_window():
    config_win = tk.Toplevel(root)
    config_win.title("⚙️ 配置腾讯云翻译")
    config_win.geometry("700x550")  # 增加高度确保显示完整
    config_win.resizable(False, False)
    config_win.configure(bg="#f5f7fa")
    
    # 居中显示
    center_window(config_win)

    # 标题样式
    title_frame = tk.Frame(config_win, bg="#f5f7fa")
    title_frame.pack(pady=(15, 10), fill="x")
    tk.Label(title_frame, text="请填写以下三项必填信息：", 
             font=("微软雅黑", 12, "bold"), bg="#f5f7fa", fg="#2c3e50").pack()

    # 输入框容器
    container = tk.Frame(config_win, bg="#f5f7fa")
    container.pack(padx=30, pady=15, fill="both", expand=True)

    # secret_id
    id_frame = tk.Frame(container, bg="#f5f7fa")
    id_frame.pack(fill="x", pady=10)
    label_id = tk.Label(id_frame, text="Secret ID：", width=15, anchor="w", 
                        font=("微软雅黑", 10), bg="#f5f7fa", fg="#34495e")
    label_id.pack(side="left", padx=(0, 15))
    id_entry = ttk.Entry(id_frame, width=50, font=("微软雅黑", 10), style="Custom.TEntry")
    id_entry.insert(0, config_data["secret_id"])
    id_entry.pack(side="right", fill="x", expand=True, ipady=5)

    # secret_key
    key_frame = tk.Frame(container, bg="#f5f7fa")
    key_frame.pack(fill="x", pady=10)
    label_key = tk.Label(key_frame, text="Secret Key：", width=15, anchor="w", 
                         font=("微软雅黑", 10), bg="#f5f7fa", fg="#34495e")
    label_key.pack(side="left", padx=(0, 15))
    key_entry = ttk.Entry(key_frame, width=50, font=("微软雅黑", 10), style="Custom.TEntry")
    key_entry.insert(0, config_data["secret_key"])
    key_entry.pack(side="right", fill="x", expand=True, ipady=5)

    # file_mapping
    map_frame = tk.Frame(container, bg="#f5f7fa")
    map_frame.pack(fill="both", expand=True, pady=10)
    label_map = tk.Label(map_frame, text="file_mapping（JSON格式）：", 
                         font=("微软雅黑", 10), bg="#f5f7fa", fg="#34495e", anchor="w")
    label_map.pack(side="top", anchor="w", pady=(0, 8))
    map_text = scrolledtext.ScrolledText(map_frame, height=8, font=("Consolas", 9), 
                                        padx=12, pady=12, relief="solid", bd=1, highlightthickness=1,
                                        highlightbackground="#dcdfe6", highlightcolor="#3498db")
    map_text.insert("1.0", json.dumps(config_data["file_mapping"], indent=2, ensure_ascii=False))
    map_text.pack(side="bottom", fill="both", expand=True)

    # 按钮样式
    btn_frame = tk.Frame(config_win, bg="#f5f7fa")
    btn_frame.pack(pady=(10, 20))

    def apply_config():
        config_data["secret_id"] = id_entry.get().strip()
        config_data["secret_key"] = key_entry.get().strip()
        try:
            config_data["file_mapping"] = json.loads(map_text.get("1.0", tk.END).strip())
        except Exception as e:
            messagebox.showerror("❌ JSON 错误", f"file_mapping 格式错误：{e}")
            return
        if save_config():
            config_win.destroy()

    save_btn = tk.Button(btn_frame, text="保存配置", command=apply_config, 
                         bg="#3498db", fg="white", font=("微软雅黑", 10, "bold"),
                         padx=20, pady=6, bd=0, activebackground="#2980b9", 
                         activeforeground="white", cursor="hand2", 
                         highlightthickness=0, relief="flat")
    save_btn.pack()
    save_btn.bind("<Enter>", lambda e: save_btn.config(bg="#2980b9"))
    save_btn.bind("<Leave>", lambda e: save_btn.config(bg="#3498db"))

# === 6️⃣ 执行翻译（核心逻辑）===
def run_translation_thread():
    # 清空日志
    log_text.delete(1.0, tk.END)
    log_text.insert(tk.END, "🔄 开始翻译...\n")
    log_text.see(tk.END)
    
    try:
        if not os.path.exists(config_file_path):
            messagebox.showwarning("⚠️ 未配置", "请先配置腾讯云 API 密钥！")
            open_config_window()
            return
        
        load_config()
        
        # 获取输入框实际值（忽略占位符）
        text = get_entry_value(text_entry)
        key = get_entry_value(key_entry)
        use_unicode = unicode_var.get() == 1
        
        # 修复语法错误：确保所有括号正确配对
        insert_line_str = get_entry_value(line_entry)
        space_count_str = get_entry_value(space_entry)
        key_space_count_str = get_entry_value(key_space_entry)
        
        # 安全转换为整数，处理空字符串
        insert_line = int(insert_line_str) if insert_line_str != "" else 0
        space_count = int(space_count_str) if space_count_str != "" else 0
        key_space_count = int(key_space_count_str) if key_space_count_str != "" else 1
        
        separator = get_entry_value(sep_entry)
        
        # 获取包裹符号值（如果为空则使用空字符串）
        value_wrapper = get_entry_value(wrapper_entry)
        if not value_wrapper:
            value_wrapper = ""

        if not text:
            messagebox.showwarning("输入错误", "请输入要翻译的中文内容！")
            return
        if not key:
            messagebox.showwarning("输入错误", "唯一 key 值必填！")
            return

        languages = list(config_data["file_mapping"].keys())
        log_text.insert(tk.END, f"🔍 开始翻译 {len(languages)} 个语言...\n")
        log_text.see(tk.END)
        
        # 禁用翻译按钮
        run_btn.config(state=tk.DISABLED, text="翻译中...", bg="#95a5a6")
        
        for target in languages:
            filename = resolve_path(config_data["file_mapping"][target])
            try:
                translation = get_translation(text, target, config_data["secret_id"], config_data["secret_key"])
                log_text.insert(tk.END, f"✅ {target} 翻译完成：{translation}\n")
                log_text.see(tk.END)
                
                value = translation
                if use_unicode:
                    value = value.encode("unicode_escape").decode("utf-8")
                
                with open(filename, "r", encoding="utf-8") as f:
                    existing_lines = f.readlines()
                
                key_exists = any(f"{key}:" in line for line in existing_lines)
                
                if key_exists:
                    result = messagebox.askyesno(
                        "⚠️ Key 已存在",
                        f"文件中已存在 key：'{key}'\n是否继续写入？"
                    )
                    if not result:
                        log_text.insert(tk.END, f"🚫 中断执行：用户取消写入 {key}\n")
                        log_text.see(tk.END)
                        continue
                
                # 使用处理后的包裹符号
                insert_key_value_at_line(
                    filename, key, value,
                    insert_line, space_count, separator,
                    key_space_count, value_wrapper
                )
                log_text.insert(tk.END, f"📝 {target} 写入 {filename}（第 {insert_line or '末'} 行，空格：{space_count}，分隔符：{separator}，key后空格：{key_space_count}，包裹：{value_wrapper if value_wrapper else '无'}）\n")
                log_text.see(tk.END)
            except Exception as e:
                log_text.insert(tk.END, f"❌ {target} 翻译失败：{e}\n")
                log_text.see(tk.END)
        
        log_text.insert(tk.END, "🎉 所有翻译完成！\n")
        log_text.see(tk.END)
        
    except Exception as e:
        log_text.insert(tk.END, f"❌ 程序错误：{e}\n")
        log_text.see(tk.END)
        messagebox.showerror("错误", str(e))
    finally:
        # 重新启用翻译按钮
        run_btn.config(state=tk.NORMAL, text="开始翻译", bg="#3498db")

def run_translation():
    # 在新线程中运行翻译，避免UI冻结
    threading.Thread(target=run_translation_thread, daemon=True).start()

# === 7️⃣ 美化 GUI：带占位符的输入框 ===
class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, placeholder="", color='#95a5a6', *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = '#2c3e50'
        
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)
        
        self.put_placeholder()
    
    def put_placeholder(self):
        self.delete(0, tk.END)
        self.insert(0, self.placeholder)
        self.config(foreground=self.placeholder_color)
    
    def _on_focus_in(self, event):
        if self.get() == self.placeholder:
            self.delete(0, tk.END)
            self.config(foreground=self.default_fg_color)
    
    def _on_focus_out(self, event):
        if not self.get():
            self.put_placeholder()
    
    def get_actual_value(self):
        """获取输入框的实际值（如果是占位符则返回空字符串）"""
        value = self.get().strip()
        if value == self.placeholder:
            return ""
        return value

# === 创建带标签的输入框 ===
def create_labeled_entry(parent, text, default="", placeholder="", width=50, validate_cmd=None):
    frame = tk.Frame(parent, bg="#f5f7fa")
    frame.pack(fill="x", padx=25, pady=5)  # 减少垂直间距

    label = tk.Label(frame, text=text, width=18, anchor="w", 
                    font=("微软雅黑", 10), bg="#f5f7fa", fg="#34495e")
    label.pack(side="left", padx=(0, 10))
    
    entry = PlaceholderEntry(frame, placeholder=placeholder, width=width, 
                            font=("微软雅黑", 10), style="Custom.TEntry")
    
    if default:
        entry.delete(0, tk.END)
        entry.insert(0, default)
        entry.config(foreground="#2c3e50")
    
    if validate_cmd:
        vcmd = (frame.register(validate_cmd), '%P')
        entry.config(validate="key", validatecommand=vcmd)
    
    entry.pack(side="right", fill="x", expand=True, ipady=4)  # 减少内边距
    
    return entry

# === 获取输入框实际值 ===
def get_entry_value(entry):
    """安全获取输入框值，忽略占位符文本"""
    if hasattr(entry, 'get_actual_value'):
        return entry.get_actual_value()
    return entry.get().strip()

# === 数字验证函数 ===
def validate_number_input(new_value):
    if new_value == "":
        return True
    return re.match(r"^\d+$", new_value) is not None

# === 窗口居中函数 ===
def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    
    # 计算居中的位置
    x = (screen_width - width) // 2
    y = (screen_height - height) // 3  # 稍微靠上一点
    
    window.geometry(f"+{x}+{y}")

# === 8️⃣ 主窗口（优化布局和交互）===
# 获取版本号 - 确保在设置标题前调用
version_info = get_version_from_resource()
root = tk.Tk()
root.title(f"中文翻译工具 🌐 v{version_info['version']}")
root.geometry("800x700")  # 优化窗口尺寸
root.resizable(True, True)
root.configure(bg="#f5f7fa")

# 设置窗口居中
center_window(root)

# 创建样式
style = ttk.Style()

# 设置主题
style.theme_use('clam')

# 自定义输入框样式
style.configure("Custom.TEntry", 
                borderwidth=2, 
                relief="solid", 
                padding=(10, 8),
                bordercolor="#bdc3c7",
                background="white",
                foreground="#2c3e50",
                font=("微软雅黑", 10),
                focuscolor="#3498db")

style.map("Custom.TEntry",
          fieldbackground=[("!disabled", "white")],
          bordercolor=[("focus", "#3498db"), ("!focus", "#bdc3c7")],
          lightcolor=[("focus", "#3498db"), ("!focus", "#bdc3c7")],
          darkcolor=[("focus", "#3498db"), ("!focus", "#bdc3c7")])

# ✅ 添加配置按钮（左上角）
top_bar = tk.Frame(root, bg="#2c3e50", height=45)
top_bar.pack(fill="x", side="top", pady=0)

config_btn = tk.Button(top_bar, text="⚙️ 配置", command=open_config_window, 
                      bg="#3498db", fg="white", font=("微软雅黑", 10, "bold"),
                      padx=15, bd=0, relief="flat", activebackground="#2980b9",
                      activeforeground="white", cursor="hand2",
                      highlightthickness=0)
config_btn.pack(side="left", padx=15, pady=8)
config_btn.bind("<Enter>", lambda e: config_btn.config(bg="#2980b9"))
config_btn.bind("<Leave>", lambda e: config_btn.config(bg="#3498db"))

# 应用标题
title_frame = tk.Frame(root, bg="#f5f7fa", padx=20, pady=10)
title_frame.pack(fill="x")

title = tk.Label(title_frame, text="中文翻译工具", font=("微软雅黑", 20, "bold"), 
                bg="#f5f7fa", fg="#2c3e50")
title.pack()

subtitle = tk.Label(title_frame, text="多语言文件自动翻译工具", font=("微软雅黑", 11), 
                   bg="#f5f7fa", fg="#7f8c8d")
subtitle.pack(pady=(0, 5))

# 主容器 - 使用Frame和Canvas实现滚动
main_canvas = tk.Canvas(root, bg="#f5f7fa", highlightthickness=0)
main_canvas.pack(side="left", fill="both", expand=True)

# 添加滚动条
scrollbar = ttk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
scrollbar.pack(side="right", fill="y")

main_canvas.configure(yscrollcommand=scrollbar.set)

# 创建主框架
main_frame = tk.Frame(main_canvas, bg="#f5f7fa")
main_canvas.create_window((0, 0), window=main_frame, anchor="nw")

# 配置鼠标滚轮滚动
def on_mousewheel(event):
    main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

main_canvas.bind_all("<MouseWheel>", on_mousewheel)
main_frame.bind("<Configure>", lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all")))

# 表单容器
form_frame = tk.Frame(main_frame, bg="white", padx=20, pady=15, 
                     relief="solid", bd=1, highlightthickness=0)
form_frame.pack(fill="x", pady=(0, 15), padx=25)

# 输入文本
text_entry = create_labeled_entry(form_frame, "输入要翻译的中文", placeholder="请输入中文内容")

# 输入 key
key_entry = create_labeled_entry(form_frame, "唯一key值", placeholder="输入唯一标识符")

# 插入行号
line_entry = create_labeled_entry(form_frame, "插入行号（0=末尾）", "0", placeholder="0表示最后一行", validate_cmd=validate_number_input)

# 插入前空格数
space_entry = create_labeled_entry(form_frame, "插入前空格数", "0", placeholder="空格数量", validate_cmd=validate_number_input)

# 行尾分隔符
sep_entry = create_labeled_entry(form_frame, "行尾分隔符", "", placeholder="例如逗号或分号")

# key: 后空格数
key_space_entry = create_labeled_entry(form_frame, "key: 后空格数", "1", placeholder="默认1", validate_cmd=validate_number_input)

# value 包裹符号（默认值为"，但允许清空）
wrapper_entry = create_labeled_entry(form_frame, "value 包裹符号", "\"", placeholder="例如引号或空（清空则不包裹）")

# Unicode 选项（紧凑布局）
unicode_frame = tk.Frame(form_frame, bg="white")
unicode_frame.pack(fill="x", padx=15, pady=8)
unicode_label = tk.Label(unicode_frame, text="启用 Unicode 编码写入：", 
                        font=("微软雅黑", 10), bg="white", fg="#34495e")
unicode_label.pack(side="left", padx=(0, 15))
unicode_var = tk.IntVar()
unicode_check = ttk.Checkbutton(unicode_frame, variable=unicode_var, style="TCheckbutton")
unicode_check.pack(side="left")

# 执行按钮（自动禁用状态：若未配置）
btn_frame = tk.Frame(main_frame, bg="#f5f7fa", pady=10)
btn_frame.pack(fill="x", padx=25)

run_btn = tk.Button(btn_frame, text="开始翻译", command=run_translation, 
                   bg="#3498db", fg="white", font=("微软雅黑", 12, "bold"),
                   padx=30, pady=8, bd=0, activebackground="#2980b9", 
                   activeforeground="white", cursor="hand2",
                   highlightthickness=0, relief="flat")
run_btn.pack()
run_btn.bind("<Enter>", lambda e: run_btn.config(bg="#2980b9"))
run_btn.bind("<Leave>", lambda e: run_btn.config(bg="#3498db"))

# 日志区域
log_frame = tk.Frame(main_frame, bg="white", relief="solid", bd=1)
log_frame.pack(fill="both", expand=True, pady=(0, 15), padx=25)

log_label = tk.Label(log_frame, text="操作日志", font=("微软雅黑", 10, "bold"), 
                    bg="#ecf0f1", fg="#2c3e50", padx=15, pady=8, anchor="w")
log_label.pack(fill="x")

log_text = scrolledtext.ScrolledText(log_frame, height=10, font=("微软雅黑", 9), 
                                    padx=12, pady=12, relief="flat", bd=0,
                                    bg="white", fg="#2c3e50")
log_text.pack(fill="both", expand=True, padx=1, pady=(0, 1))

# 状态栏
status_bar = tk.Frame(root, bg="#2c3e50", height=30)
status_bar.pack(fill="x", side="bottom")
status_label = tk.Label(status_bar, text="就绪", fg="white", bg="#2c3e50", 
                       font=("微软雅黑", 9), anchor="w", padx=15)
status_label.pack(fill="x")

# === 9️⃣ 检查远程版本 ===
def check_exe_update():
    try:
        remote_url = "https://raw.githubusercontent.com/keithuddc/translator/refs/heads/main/config.json"
        resp = requests.get(remote_url, timeout=5, verify=False)
        
        # 关键：先检查状态码，再解析 JSON
        if resp.status_code != 200:
            print(f"❌ HTTP 错误：{resp.status_code} - 接口返回非 200")
            return

        # 关键：使用 try-except 包裹 json.loads，防止空或非法 JSON
        try:
            remote = resp.json()
        except json.JSONDecodeError as e:
            print(f"❌ JSON 解析失败：{e}，响应内容：{resp.text[:200]}")
            return

        # 正常逻辑：比对版本
        local_version = version_info["version"]
        if remote["version"] != local_version:
            status_label.config(text="检测到新版本，请点击配置按钮更新")
            messagebox.showinfo(
                "⚠️ 有新版本",
                f"当前版本：{local_version}\n最新版本：{remote['version']}\n\n更新日志：{remote.get('changelog', '暂无日志')}\n\n点击确定下载最新版本。"
            )
            import webbrowser
            webbrowser.open(remote["download_url"])
        else:
            status_label.config(text="已是最新版本")
    
    except requests.exceptions.RequestException as e:
        status_label.config(text="更新检查失败: 网络错误")
        print(f"❌ 网络请求失败：{e}")
    except Exception as e:
        status_label.config(text="更新检查失败: 未知错误")
        print(f"❌ 未知错误：{e}")

# 启动后自动检查版本
root.after(1000, check_exe_update)

# 启动主循环
root.mainloop()
