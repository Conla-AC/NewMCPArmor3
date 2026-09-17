#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full Tkinter UI for the MCP Armor Python 2.7 backend."""

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from MCP_Armor_Src.hwid import validate_license


APP_TITLE = "MCP Shiled 混淆器"
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
ARGV_DIR = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else PACKAGE_DIR


def _is_nuitka_compiled():
    try:
        __compiled__
    except NameError:
        return False
    return True


# PyInstaller exposes sys.frozen. Nuitka onefile preserves the outer EXE in
# argv[0], while __file__ points at its temporary extraction directory.
ARGV_IS_EXE = bool(sys.argv and os.path.abspath(sys.argv[0]).lower().endswith(
    (".exe", ".com")))
FROZEN = bool(getattr(sys, "frozen", False) or _is_nuitka_compiled()
              or ARGV_IS_EXE)
APP_DIR = (ARGV_DIR if FROZEN and ARGV_IS_EXE else
           (os.path.dirname(os.path.abspath(sys.executable))
            if FROZEN else PACKAGE_DIR))
ROOT_DIR = APP_DIR if FROZEN else os.path.dirname(PACKAGE_DIR)


def _unique_dirs(paths):
    result = []
    seen = set()
    for path in paths:
        if not path:
            continue
        path = os.path.abspath(path)
        key = os.path.normcase(path)
        if key not in seen:
            seen.add(key)
            result.append(path)
    return tuple(result)


RUNTIME_DIRS = _unique_dirs((
    getattr(sys, "_MEIPASS", None),
    APP_DIR,
    ARGV_DIR,
    os.getcwd(),
    PACKAGE_DIR,
))


def _find_resource_dir():
    for base in RUNTIME_DIRS:
        if os.path.isfile(os.path.join(base, "assets", "Logo.png")):
            return base
    return APP_DIR if FROZEN else PACKAGE_DIR


RESOURCE_DIR = _find_resource_dir()
STATE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", APP_DIR), "MCPArmor")
# The source tree uses the package entry point; a root-level main.py is only
# kept as a legacy fallback for older distributions.
OBFUSCATOR = os.path.join(ROOT_DIR, "main.py")
OBFUSCATOR_MODULE = os.path.join(ROOT_DIR, "MCP_Armor_Src", "__main__.py")
OBFUSCATOR_EXE_NAMES = [
    "01_MCPArmor_CLI_protected.exe",
    "01_MCPArmor_CLI.exe",
    "Py27ByteObf.exe",
    "Py27ByteObf_Self.exe",
    "Py27ByteObf_NeteaseSelf.exe",
]
LOGO_PATH = os.path.join(RESOURCE_DIR, "assets", "Logo.png")
RUN_CONFIG = os.path.join(STATE_DIR, "run_config.yml")
RUN_LOG = os.path.join(STATE_DIR, "last_run.log")


def shell_quote(value):
    return '"' + str(value).replace('"', '\\"') + '"'


def format_command(argv):
    return " ".join(shell_quote(part) for part in argv)


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def write_text(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


def find_obfuscator_exe():
    parent = os.path.dirname(APP_DIR)
    search_dirs = _unique_dirs(RUNTIME_DIRS + (
        RESOURCE_DIR,
        ROOT_DIR,
        parent,
        os.path.join(APP_DIR, "01_CLI"),
        os.path.join(parent, "01_CLI"),
    ))
    for base in search_dirs:
        nested = os.path.join(base, "Py27ByteObf", "Py27ByteObf.exe")
        if os.path.exists(nested):
            return nested
    for name in OBFUSCATOR_EXE_NAMES:
        for base in search_dirs:
            path = os.path.join(base, name)
            if os.path.exists(path):
                return path
    return None


def find_obfuscator_cwd():
    exe = find_obfuscator_exe()
    if exe:
        return os.path.dirname(os.path.abspath(exe))
    return ROOT_DIR if os.path.isdir(os.path.join(ROOT_DIR, "MCP_Armor_Src")) else APP_DIR


def yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = "" if value is None else str(value)
    if text == "":
        return '""'
    return '"' + text.replace("\\", "/").replace('"', '\\"') + '"'


def parse_yaml_scalar(value):
    value = value.strip()
    if value == "":
        return ""
    low = value.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    if ((value.startswith('"') and value.endswith('"')) or
            (value.startswith("'") and value.endswith("'"))):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_yaml_scalar(part) for part in inner.split(",")]
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return value


def read_simple_yaml(path):
    data = {}
    stack = [(-1, data)]
    pending_lists = {}
    for raw in read_text(path).splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if text.startswith("- "):
            key = pending_lists.get(indent)
            if key is not None:
                if not isinstance(parent.get(key), list):
                    parent[key] = []
                parent[key].append(parse_yaml_scalar(text[2:].strip()))
            continue
        if ":" not in text:
            continue
        key, value = text.split(":", 1)
        key = key.strip().replace("-", "_")
        value = value.strip()
        if value == "":
            child = {}
            parent[key] = child
            stack.append((indent, child))
            pending_lists[indent + 2] = key
        else:
            parent[key] = parse_yaml_scalar(value)
            pending_lists[indent + 2] = key
    return data


def flatten_config(config, prefix=""):
    flat = {}
    for key, value in config.items():
        name = (prefix + "_" + key) if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_config(value, name))
        else:
            flat[name] = value
            flat[key] = value
    return flat


class Splash(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.overrideredirect(True)
        self.configure(bg="#101418")
        self.image = None
        frame = tk.Frame(self, bg="#101418", padx=24, pady=24)
        frame.pack(fill="both", expand=True)
        if os.path.exists(LOGO_PATH):
            try:
                self.image = tk.PhotoImage(file=LOGO_PATH)
                tk.Label(frame, image=self.image, bg="#101418").pack()
            except tk.TclError:
                tk.Label(frame, text=APP_TITLE, fg="#f2f5f7", bg="#101418", font=("Segoe UI", 20, "bold")).pack()
        else:
            tk.Label(frame, text=APP_TITLE, fg="#f2f5f7", bg="#101418", font=("Segoe UI", 20, "bold")).pack()
        tk.Label(frame, text="正在加载混淆器界面……", fg="#b8c0c8", bg="#101418", font=("Microsoft YaHei UI", 10)).pack(pady=(12, 0))
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry("%dx%d+%d+%d" % (w, h, x, y))


class ScrollFrame(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0, bg="#f5f7f9")
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.body = ttk.Frame(self.canvas)
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.body.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.window, width=e.width))
        self.canvas.bind_all("<MouseWheel>", self._wheel)

    def _wheel(self, event):
        if self.winfo_ismapped():
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class ObfUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.title(APP_TITLE)
        self.geometry("1220x820")
        self.minsize(1060, 720)
        self.vars = {}
        self.status = tk.StringVar(value="就绪")
        self.running = False
        self._setup_style()
        splash = Splash(self)
        self.after(800, lambda: self._show_main(splash))

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#f5f7f9")
        style.configure("TLabel", background="#f5f7f9", font=("Microsoft YaHei UI", 9))
        style.configure("TButton", font=("Microsoft YaHei UI", 9), padding=(10, 5))
        style.configure("TCheckbutton", background="#f5f7f9", font=("Microsoft YaHei UI", 9))
        style.configure("Card.TLabelframe", background="#f5f7f9", padding=10)
        style.configure("Card.TLabelframe.Label", background="#f5f7f9", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TNotebook.Tab", font=("Microsoft YaHei UI", 9), padding=(14, 7))

    def _show_main(self, splash):
        splash.destroy()
        self._build()
        self.deiconify()
        self.lift()
        self.after(80, self._check_environment)

    def v(self, name, default=""):
        if isinstance(default, bool):
            var = tk.BooleanVar(value=default)
        elif isinstance(default, int):
            var = tk.IntVar(value=default)
        else:
            var = tk.StringVar(value=default)
        self.vars[name] = var
        return var

    def _build(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        header = ttk.Frame(root)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="MCP Shiled 网易 Python 混淆器", font=("Microsoft YaHei UI", 18, "bold")).pack(side="left")
        ttk.Label(header, textvariable=self.status).pack(side="right")
        main = ttk.Frame(root)
        main.pack(fill="both", expand=True)
        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(main, width=360)
        right.pack(side="right", fill="y", padx=(12, 0))
        right.pack_propagate(False)
        notebook = ttk.Notebook(left)
        notebook.pack(fill="both", expand=True)
        self._project_tab(notebook)
        self._profile_tab(notebook)
        self._source_tab(notebook)
        self._payload_tab(notebook)
        self._bytecode_tab(notebook)
        self._loader_tab(notebook)
        self._advanced_tab(notebook)
        self._actions(right)
        self._log_panel(root)

    def group(self, parent, title):
        frame = ttk.LabelFrame(parent, text=title, style="Card.TLabelframe")
        frame.pack(fill="x", padx=4, pady=8)
        for col in range(6):
            frame.columnconfigure(col, weight=1 if col % 2 else 0)
        return frame

    def check(self, parent, row, col, name, text):
        ttk.Checkbutton(parent, text=text, variable=self.vars[name]).grid(row=row, column=col, sticky="w", padx=4, pady=4, columnspan=2)

    def entry(self, parent, row, label, name, col=0, width=18):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=4, pady=4)
        ttk.Entry(parent, textvariable=self.vars[name], width=width).grid(row=row, column=col + 1, sticky="ew", padx=4, pady=4)

    def combo(self, parent, row, label, name, values, col=0):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", padx=4, pady=4)
        ttk.Combobox(parent, textvariable=self.vars[name], values=values, state="readonly").grid(row=row, column=col + 1, sticky="ew", padx=4, pady=4)

    def path_group(self, parent, title, name, command):
        box = self.group(parent, title)
        ttk.Entry(box, textvariable=self.vars[name]).grid(row=0, column=0, sticky="ew", padx=4, pady=4, columnspan=5)
        ttk.Button(box, text="浏览…", command=command).grid(row=0, column=5, padx=4, pady=4)

    def _project_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="项目")
        b = tab.body
        self.v("input", os.path.join(ROOT_DIR, "ScriptMod copy 2"))
        self.v("output", os.path.join(ROOT_DIR, "ScriptMod_ui_out"))
        self.v("folder", True)
        self.v("clean_output", True)
        self.v("copy_pyc", False)
        self.v("emit_pyc", False)
        self.v("obfuscate_modmain", False)
        self.v("target_side", "all")
        self.v("include", "*.py")
        self.v("exclude", "modMain.py;__init__.py")
        self.v("plain_copy", "")
        self.v("deploy_target", "")
        self.v("output_date", "2012-03-15")
        self.path_group(b, "输入文件或项目目录", "input", self.pick_input)
        self.path_group(b, "输出文件或项目目录", "output", self.pick_output)
        self.path_group(b, "部署目标目录（可留空）", "deploy_target", self.pick_deploy)
        mode = self.group(b, "项目处理方式")
        self.check(mode, 0, 0, "folder", "目录模式（--folder）")
        self.check(mode, 0, 2, "clean_output", "运行前清空输出目录")
        self.check(mode, 1, 0, "copy_pyc", "复制原有 .pyc 文件")
        self.check(mode, 1, 2, "obfuscate_modmain", "同时混淆 modMain.py")
        self.check(mode, 2, 0, "emit_pyc", "直接输出 Python 2.7 .pyc")
        self.combo(mode, 3, "目标侧", "target_side", ["all", "server", "client"])
        filters = self.group(b, "文件筛选（多个规则用分号分隔）")
        self.entry(filters, 0, "包含规则", "include", width=48)
        self.entry(filters, 1, "排除混淆", "exclude", width=48)
        self.entry(filters, 2, "原样复制", "plain_copy", width=48)
        self.entry(filters, 3, "输出日期（水印/pyc）", "output_date", width=24)

    def _profile_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="档位")
        b = tab.body
        self.v("preset", "safe")
        self.v("resource_profile", "balanced")
        self.v("netease_profile", "strong-plus")
        self.v("key_len", 16)
        self.v("loader_mode", "netease-func")
        self.v("filename_mode", "mem")
        self.v("header_mode", "docstring")
        self.v("mcs_opmap_version", 1)
        self.v("fix_netease_register", True)
        self.v("package_name", "NeteaseMod")
        self.v("namespace", "Script_NeteaseMod")
        self.v("debug", False)
        core = self.group(b, "核心档位")
        self.combo(core, 4, "资源预算", "resource_profile", ["compact", "balanced", "strong", "unlimited"])
        self.combo(core, 0, "基础强度", "preset", ["none", "safe", "strong", "max", "experimental"])
        self.combo(core, 1, "网易预设", "netease_profile", ["none", "safe", "strong", "strong-plus", "diagnostic"])
        self.entry(core, 2, "密钥长度", "key_len")
        self.combo(core, 0, "加载器模式", "loader_mode", ["netease-func", "cpickle", "function", "marshal", "source"], col=2)
        self.combo(core, 1, "文件名模式", "filename_mode", ["mem", "module", "keep"], col=2)
        self.entry(core, 2, "MCS Opcode 映射版本", "mcs_opmap_version", col=2)
        self.check(core, 3, 0, "debug", "全阶段调试日志（[DEBUG]）")
        self.combo(core, 3, "标题模式", "header_mode", ["docstring", "comment"], col=2)
        reg = self.group(b, "网易注册修复")
        self.check(reg, 0, 0, "fix_netease_register", "修复 modMain RegisterSystem 路径")
        self.entry(reg, 1, "包名", "package_name", width=34)
        self.entry(reg, 2, "命名空间", "namespace", width=34)

    def _source_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="源码 AST")
        b = tab.body
        defaults = {
            "source_linearize_calls": True, "source_schedule": True,
            "source_schedule_max_exprs": 4, "source_schedule_window": 8,
            "source_global_rename": True,
            "source_module_rename": False,
            "source_function_split": False,
            "source_module_rename_exclude": "modMain.py;config.py;__init__.py",
            "source_string_split": False, "source_string_split_parts": 3,
            "source_string_xor": False, "source_string_xor_mode": "random",
            "source_string_xor_text": "MCP_Shiled", "source_string_xor_number": 173,
            "source_string_xor_min_length": 4, "source_string_xor_limit": 512,
            "source_string_xor_variants": 4, "source_string_xor_decoys": 2,
            "source_string_xor_debug": False,
            "source_constant_pool": False, "source_constant_pool_min": 4,
            "source_constant_pool_max": 128, "source_constant_rewrite": False,
            "source_constant_rewrite_limit": 8, "source_exception_shell": False,
            "source_parenthesis_noise": False, "source_comment_noise": False,
            "source_comment_noise_count": 2, "source_dead_flow": True,
            "source_dead_flow_blocks": 1,
            "source_vm": False, "source_vm_full": False,
            "source_vm_ratio": 15, "source_vm_min_ops": 8,
            "source_vm_max_ops": 160, "source_vm_max_functions": 8,
            "source_vm_include": "", "source_vm_exclude": "On*;*Tick*;*Update*;*Timer*;*Frame*;*Render*;Listen*;Notify*;NeteaseMod*;__*__",
            "source_vm_allow_loops": False, "source_vm_debug": False,
            "source_flow_hardening": False,
            "source_project_analysis": True,
            "source_internal_predicates": False,
            "source_internal_predicate_ratio": 70,
            "source_hot_pattern": "On*;*Tick*;*Update*;*Timer*;*Frame*;*Render*;Listen*;Notify*;Callback;Destroy;__*__",
            "source_vm_dialects": 4,
            "source_vm_flow_constants": False,
            "source_vm_exception_trap_ratio": 2,
            "source_reference_obf": False, "source_reference_obf_ratio": 35,
            "source_reference_obf_exclude": "__*__;func_*;co_*",
            "source_tuple_arg_decoys": 2, "source_dotzero_relay": True,
            "source_default_capsule": True, "source_identity_weave": True,
            "source_identity_ratio": 45, "source_identity_max": 12,
            "source_identity_variation": True, "source_decompiler_carriers": 1,
            "source_exception_lattice": True, "source_class_body_trap": True,
            "source_decoy_docstrings": False,
            "source_decoy_docstring_min": 1024,
            "source_decoy_docstring_max": 4096,
            "control_flow_flatten": False, "control_flow_max_blocks": 18,
        }
        for name, value in defaults.items():
            self.v(name, value)
        self.v("disable_ast", False)
        self.v("no_bytecode_obf", False)
        self.v("source_only", "NeteaseClientSystem.py;uiScript/*.py")
        self.v("ast_exclude", "")
        basic = self.group(b, "低开销源码变换")
        self.check(basic, 0, 0, "source_linearize_calls", "调用链线性化")
        self.check(basic, 0, 2, "source_schedule", "表达式调度与安全重排")
        self.check(basic, 1, 0, "source_global_rename", "全项目统一 Rename")
        self.check(basic, 1, 2, "source_module_rename", "Python 文件名混淆与注册重定位")
        self.check(basic, 1, 4, "source_function_split", "函数/类方法拆分为独立模块")
        self.check(basic, 2, 0, "source_string_split", "字符串分片")
        self.check(basic, 2, 2, "source_constant_pool", "局部常量池")
        self.check(basic, 3, 0, "source_constant_rewrite", "整数常量等价改写")
        self.check(basic, 3, 2, "source_exception_shell", "异常结构外壳")
        self.check(basic, 4, 0, "source_parenthesis_noise", "无意义括号噪音")
        self.check(basic, 4, 2, "source_comment_noise", "注释与空白噪音")
        self.check(basic, 5, 0, "source_dead_flow", "死代码与伪控制流")
        self.entry(basic, 7, "字符串分片数", "source_string_split_parts")
        self.entry(basic, 7, "常量改写上限", "source_constant_rewrite_limit", col=2)
        self.entry(basic, 8, "常量池最小值", "source_constant_pool_min")
        self.entry(basic, 8, "常量池最大值", "source_constant_pool_max", col=2)
        self.entry(basic, 9, "死代码块数", "source_dead_flow_blocks")
        self.entry(basic, 9, "注释噪音数量", "source_comment_noise_count", col=2)
        self.entry(basic, 10, "调度表达式上限", "source_schedule_max_exprs")
        self.entry(basic, 10, "调度窗口", "source_schedule_window", col=2)
        self.entry(basic, 11, "文件名 Rename 排除", "source_module_rename_exclude")

        string_box = self.group(b, "字符串异或加密")
        self.check(string_box, 0, 0, "source_string_xor", "启用字符串异或加密")
        self.check(string_box, 0, 2, "source_string_xor_debug", "打印字符串解密调试日志")
        self.combo(string_box, 1, "密钥模式", "source_string_xor_mode", ["random", "text", "number"])
        self.entry(string_box, 1, "文本密钥", "source_string_xor_text", col=2, width=28)
        self.entry(string_box, 2, "数字密钥", "source_string_xor_number")
        self.entry(string_box, 2, "最短字符串", "source_string_xor_min_length", col=2)
        self.entry(string_box, 3, "每文件加密上限", "source_string_xor_limit")
        self.entry(string_box, 3, "真实解密器变体", "source_string_xor_variants", col=2)
        self.entry(string_box, 4, "伪解密器数量", "source_string_xor_decoys")

        vm = self.group(b, "AST 虚拟机（VM）· 支持闭包/with/try-finally/生成器")
        self.check(vm, 0, 0, "source_vm", "启用随机寄存器 VM")
        self.check(vm, 0, 2, "source_vm_allow_loops", "允许虚拟化循环（更慢）")
        self.check(vm, 1, 2, "source_vm_full", "完整 VM（保留热路径排除）")
        self.check(vm, 1, 0, "source_vm_debug", "打印 VM 安装调试日志")
        self.entry(vm, 2, "函数命中比例（%）", "source_vm_ratio")
        self.entry(vm, 2, "每文件函数上限", "source_vm_max_functions", col=2)
        self.entry(vm, 3, "最小操作数", "source_vm_min_ops")
        self.entry(vm, 3, "最大操作数", "source_vm_max_ops", col=2)
        self.entry(vm, 4, "包含函数规则", "source_vm_include", width=52)
        self.entry(vm, 5, "排除函数规则", "source_vm_exclude", width=52)
        self.check(vm, 6, 0, "source_flow_hardening", "Skid 流谓词强化（1-7）")
        self.check(vm, 6, 2, "source_project_analysis", "全项目调用分析")
        self.check(vm, 7, 0, "source_internal_predicates", "内部函数隐藏谓词参数")
        self.entry(vm, 7, "谓词函数比例（%）", "source_internal_predicate_ratio", col=2)
        self.entry(vm, 8, "热路径排除规则", "source_hot_pattern", width=52)
        self.entry(vm, 9, "VM 方言族数量", "source_vm_dialects")
        self.check(vm, 9, 2, "source_vm_flow_constants", "常量/名称绑定流状态")
        self.entry(vm, 10, "失败异常陷阱比例（%）", "source_vm_exception_trap_ratio")
        self.check(vm, 11, 0, "source_reference_obf", "多态引用混淆")
        self.entry(vm, 12, "引用改写比例（%）", "source_reference_obf_ratio")
        self.entry(vm, 13, "引用排除规则", "source_reference_obf_exclude", width=52)

        anti = self.group(b, "反编译结构干扰")
        self.entry(anti, 0, "Tuple 参数诱饵", "source_tuple_arg_decoys")
        self.check(anti, 0, 2, "source_dotzero_relay", ".0 生成器中继")
        self.check(anti, 1, 0, "source_default_capsule", "函数默认值胶囊")
        self.check(anti, 1, 2, "source_identity_weave", "函数身份编织")
        self.entry(anti, 2, "身份编织比例（%）", "source_identity_ratio")
        self.entry(anti, 2, "身份编织上限", "source_identity_max", col=2)
        self.check(anti, 3, 0, "source_identity_variation", "随机化 Code/Default/Doc 角色")
        self.entry(anti, 3, "递归 Code 载体（0-4）", "source_decompiler_carriers", col=2)
        self.check(anti, 4, 0, "source_exception_lattice", "异常控制流格")
        self.check(anti, 4, 2, "source_class_body_trap", "类体作用域陷阱")
        self.check(anti, 5, 0, "source_decoy_docstrings", "乱码 Docstring 诱饵")
        self.entry(anti, 6, "Docstring 最小字节", "source_decoy_docstring_min")
        self.entry(anti, 6, "Docstring 最大字节", "source_decoy_docstring_max", col=2)

        scope = self.group(b, "按文件关闭与实验功能")
        self.check(scope, 0, 0, "no_bytecode_obf", "全部关闭字节码混淆，仅保留源码层")
        self.check(scope, 0, 2, "disable_ast", "全部关闭源码 AST 混淆")
        self.check(scope, 1, 0, "control_flow_flatten", "实验性控制流平坦化")
        self.entry(scope, 1, "平坦化块上限", "control_flow_max_blocks", col=2)
        self.entry(scope, 2, "仅源码混淆文件", "source_only", width=52)
        self.entry(scope, 3, "关闭 AST 的文件", "ast_exclude", width=52)

    def _payload_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="载荷与 Code 对象")
        b = tab.body
        defaults = {
            "code_tuple_payload": True, "code_bytes_split": True, "code_bytes_split_min": 48,
            "code_bytes_split_max_chunks": 6, "code_bytes_fake_chunks": 4,
            "code_ref_table": True, "code_ref_decoys": 8, "code_ref_wide_rows": True,
            "code_ref_mask_markers": True, "code_tuple_field_shuffle": True,
            "code_tuple_fragments": True, "code_tuple_fragment_providers": True,
            "code_tuple_provider_graph": True, "code_tuple_provider_decoys": 6,
            "code_capsule_proxy": True, "code_capsule_protocol_guard": True,
            "lazy_function_capsules": True, "lazy_capsule_ratio": 20,
            "lazy_capsule_max_functions": 8, "lazy_capsule_mode": "adaptive",
            "lazy_capsule_retain_calls": 4, "lazy_capsule_include": "",
            "lazy_capsule_cross_key": True, "lazy_capsule_rotate_payload": False,
            "lazy_capsule_rotate_max_bytes": 262144,
            "lazy_capsule_carrier_swap": False,
            "lazy_capsule_manager_proxy": True,
            "lazy_capsule_carrier_route_rotation": False,
            "lazy_capsule_exclude": "On*;*Tick*;*Update*;*Timer*;*Frame*;*Render*;Listen*;Notify*;NeteaseMod*;__*__",
            "lazy_capsule_debug": False,
            "code_field_descriptors": True, "code_provider_context_bind": True,
            "code_fused_restore": True, "loader_reference_cleanup": True,
            "code_global_arena": False, "code_template_delta": False,
            "code_global_arena_decoys": 0, "code_block_relocation": False,
            "code_block_reloc_decoys": 0, "code_unit_arena": False,
            "code_unit_arena_decoys": 0, "code_operand_graph": False,
            "code_const_arena": False, "code_const_arena_decoys": 0,
            "code_const_provider_graph": False, "code_const_arena_limit": 1024,
            "payload_splits": 3, "payload_graph_split": True, "fake_payload_mirrors": 2,
            "payload_graph_decoys": 16,
        }
        for k, v in defaults.items():
            self.v(k, v)
        code = self.group(b, "Code Tuple 载荷")
        names = ["code_tuple_payload", "code_bytes_split", "code_ref_table", "code_ref_wide_rows", "code_ref_mask_markers", "code_tuple_field_shuffle", "code_tuple_fragments", "code_tuple_fragment_providers", "code_tuple_provider_graph"]
        labels = {
            "code_tuple_payload": "递归 cPickle Code Tuple",
            "code_bytes_split": "拆分 co_code 字节",
            "code_ref_table": "嵌套 Code 引用表",
            "code_ref_wide_rows": "引用表宽行噪音",
            "code_ref_mask_markers": "引用标记掩码",
            "code_tuple_field_shuffle": "CodeType 字段乱序",
            "code_tuple_fragments": "CodeType 字段分片",
            "code_tuple_fragment_providers": "分片 Provider 包装",
            "code_tuple_provider_graph": "Provider 依赖图",
        }
        for row, name in enumerate(names):
            self.check(code, row, 0, name, labels[name])
        self.entry(code, 1, "最小拆分长度", "code_bytes_split_min", col=2)
        self.entry(code, 2, "最大分片数", "code_bytes_split_max_chunks", col=2)
        self.entry(code, 3, "伪字节分片", "code_bytes_fake_chunks", col=2)
        self.entry(code, 4, "引用表诱饵", "code_ref_decoys", col=2)
        self.entry(code, 8, "Provider 诱饵", "code_tuple_provider_decoys", col=2)

        provider = self.group(b, "Code Provider 与执行胶囊")
        self.check(provider, 0, 0, "code_capsule_proxy", "闭包调用代理胶囊")
        self.check(provider, 0, 2, "code_capsule_protocol_guard", "胶囊协议保护")
        self.check(provider, 1, 0, "code_field_descriptors", "14 字段描述器/Provider")
        self.check(provider, 1, 2, "code_provider_context_bind", "Provider 上下文绑定")
        self.check(provider, 2, 0, "code_fused_restore", "融合 Opcode/Operand 恢复")
        self.check(provider, 2, 2, "loader_reference_cleanup", "执行前清理载荷引用")

        lazy = self.group(b, "Lazy Capsule 3.0（跨层绑定与轮换）")
        self.check(lazy, 0, 0, "lazy_function_capsules", "启用函数级独立加密载荷")
        self.check(lazy, 0, 2, "lazy_capsule_debug", "打印装载/驱逐调试日志")
        self.check(lazy, 1, 0, "lazy_capsule_cross_key", "绑定外层模块运行时密钥")
        self.check(lazy, 1, 2, "lazy_capsule_rotate_payload", "装载后重新加密并轮换载荷")
        self.check(lazy, 2, 0, "lazy_capsule_carrier_swap", "真实 code 临时换入独立诱饵函数载体")
        self.check(lazy, 2, 2, "lazy_capsule_manager_proxy", "管理闭包封装为协议保护 callable")
        self.check(lazy, 3, 0, "lazy_capsule_carrier_route_rotation", "三种 func_code 写入通道动态轮换")
        self.entry(lazy, 4, "函数命中比例（%）", "lazy_capsule_ratio")
        self.entry(lazy, 4, "每文件函数上限", "lazy_capsule_max_functions", col=2)
        self.combo(lazy, 5, "驻留策略", "lazy_capsule_mode", ["adaptive", "once", "count", "call"])
        self.entry(lazy, 5, "计数驻留调用数", "lazy_capsule_retain_calls", col=2)
        self.entry(lazy, 6, "轮换载荷大小上限", "lazy_capsule_rotate_max_bytes")
        self.entry(lazy, 7, "包含函数规则", "lazy_capsule_include", width=52)
        self.entry(lazy, 8, "排除热点函数规则", "lazy_capsule_exclude", width=52)

        arena = self.group(b, "Code Object 动态拼接与 Arena")
        self.check(arena, 0, 0, "code_global_arena", "模块级字段 Global Arena")
        self.check(arena, 0, 2, "code_template_delta", "模板差量节点")
        self.entry(arena, 1, "Global Arena 诱饵", "code_global_arena_decoys")
        self.check(arena, 1, 2, "code_block_relocation", "基本块重定位")
        self.entry(arena, 2, "基本块诱饵", "code_block_reloc_decoys")
        self.check(arena, 2, 2, "code_unit_arena", "指令单元 Arena")
        self.entry(arena, 3, "指令单元诱饵", "code_unit_arena_decoys")
        self.check(arena, 3, 2, "code_operand_graph", "Opcode/Operand 掩码图")
        self.check(arena, 4, 0, "code_const_arena", "模块常量 Arena")
        self.check(arena, 4, 2, "code_const_provider_graph", "常量 Provider 图")
        self.entry(arena, 5, "常量 Arena 诱饵", "code_const_arena_decoys")
        self.entry(arena, 5, "常量迁移上限", "code_const_arena_limit", col=2)

        graph = self.group(b, "外层载荷图")
        self.check(graph, 0, 0, "payload_graph_split", "载荷图拆分")
        self.entry(graph, 0, "载荷分片数", "payload_splits", col=2)
        self.entry(graph, 1, "伪镜像数量", "fake_payload_mirrors")
        self.entry(graph, 1, "图节点诱饵", "payload_graph_decoys", col=2)

    def _bytecode_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="字节码")
        b = tab.body
        defaults = {
            "const_noise": "", "tail_noise": "", "bytecode_stack_pad": 8,
            "bytecode_lnotab_noise": 6, "bytecode_const_salts": 10,
            "bytecode_name_chaff": 12, "const_swamp": 16, "root_const_swamp": 192,
            "const_ref_chains": 12, "index_pool_shuffle": True, "index_pool_mirrors": 8,
            "bytecode_entry_noise": 0, "bytecode_exception_decoys": 0,
            "bytecode_stack_noise": False, "bytecode_stack_noise_interval": 18,
            "bytecode_stack_noise_limit": 6, "bytecode_jump_inversion": False,
            "bytecode_jump_inversion_limit": 4, "bytecode_jump_trampolines": False,
            "bytecode_jump_trampoline_limit": 4, "bytecode_flow": False,
            "bytecode_flow_ratio": 35, "bytecode_flow_max_edges": 6,
            "bytecode_flow_loop_dispatch": False,
            "bytecode_flow_block_seeds": False,
            "bytecode_flow_block_seed_ratio": 35,
            "bytecode_flow_block_seed_max_blocks": 64,
            "bytecode_flow_block_shuffle": False,
            "bytecode_flow_block_shuffle_ratio": 35,
            "bytecode_flow_block_shuffle_max_blocks": 192,
            "bytecode_strategy_variation": False,
            "bytecode_strategy_seed": 0, "bytecode_delayed_const_access": False,
            "bytecode_delayed_const_limit": 3, "bytecode_extended_arg_prefix": False,
            "bytecode_extended_arg_interval": 11, "bytecode_extended_arg_limit": 6,
            "slot_mirage": True, "slot_mirage_limit": 8,
            "bytecode_split_gates": False, "bytecode_split_interval": 18,
            "bytecode_split_bad_units": 2, "bytecode_split_nop_bloat": 2,
            "split_adaptive": False, "loop_shadow_gates": False,
            "bytecode_opaque_predicates": True, "bytecode_opaque_interval": 28,
            "bytecode_opaque_width": 2, "bytecode_opaque_limit": 2,
            "real_block_reorder": False, "real_block_reorder_limit": 2,
            "safe_dead_blocks": False, "bytecode_taken_jump_poison": False,
            "safe_dead_interval": 20,
            "safe_dead_width": 4, "safe_dead_limit": 6, "oparg_poison": False,
            "bytecode_decoy_islands": False,
            "bytecode_decoy_island_ratio": 20,
            "bytecode_decoy_island_limit": 2,
            "bytecode_decoy_island_width": 4,
            "bytecode_decoy_island_growth": 15,
        }
        for k, v in defaults.items():
            self.v(k, v)
        structural = self.group(b, "结构与常量池")
        self.entry(structural, 0, "常量噪音", "const_noise")
        self.entry(structural, 0, "尾部噪音", "tail_noise", col=2)
        self.entry(structural, 1, "栈深度膨胀", "bytecode_stack_pad")
        self.entry(structural, 1, "行号表噪音", "bytecode_lnotab_noise", col=2)
        self.entry(structural, 2, "常量盐", "bytecode_const_salts")
        self.entry(structural, 2, "名称碎屑", "bytecode_name_chaff", col=2)
        self.entry(structural, 3, "常量沼泽", "const_swamp")
        self.entry(structural, 3, "根常量沼泽", "root_const_swamp", col=2)
        self.entry(structural, 4, "常量引用链", "const_ref_chains")
        self.check(structural, 4, 2, "index_pool_shuffle", "索引池乱序")
        self.entry(structural, 5, "索引池镜像", "index_pool_mirrors")
        self.entry(structural, 5, "入口合法噪音", "bytecode_entry_noise", col=2)
        self.entry(structural, 6, "异常结构诱饵", "bytecode_exception_decoys")

        transforms = self.group(b, "真实字节码等价变换")
        self.check(transforms, 0, 0, "bytecode_stack_noise", "内部栈等价噪音")
        self.entry(transforms, 0, "噪音间隔", "bytecode_stack_noise_interval", col=2)
        self.entry(transforms, 1, "栈噪音上限", "bytecode_stack_noise_limit")
        self.check(transforms, 1, 2, "bytecode_jump_inversion", "条件跳转反转")
        self.entry(transforms, 2, "跳转反转上限", "bytecode_jump_inversion_limit")
        self.check(transforms, 2, 2, "bytecode_jump_trampolines", "两级跳转蹦床")
        self.entry(transforms, 3, "跳转蹦床上限", "bytecode_jump_trampoline_limit")
        self.check(transforms, 3, 2, "bytecode_strategy_variation", "按 Code 随机策略组合")
        self.entry(transforms, 4, "策略随机种子", "bytecode_strategy_seed")
        self.check(transforms, 4, 2, "bytecode_delayed_const_access", "延迟常量访问")
        self.entry(transforms, 5, "延迟常量上限", "bytecode_delayed_const_limit")
        self.check(transforms, 5, 2, "bytecode_extended_arg_prefix", "EXTENDED_ARG 0 前缀")
        self.entry(transforms, 6, "EXTENDED_ARG 间隔", "bytecode_extended_arg_interval")
        self.entry(transforms, 6, "EXTENDED_ARG 上限", "bytecode_extended_arg_limit", col=2)
        self.check(transforms, 7, 0, "slot_mirage", ".N 局部槽位海市蜃楼")
        self.entry(transforms, 7, "槽位改名上限", "slot_mirage_limit", col=2)

        self.check(transforms, 8, 0, "bytecode_flow", "ByteCode_Flow 控制流代理")
        self.entry(transforms, 8, "ByteCode_Flow 选择比例", "bytecode_flow_ratio", col=2)
        self.entry(transforms, 9, "ByteCode_Flow 单函数上限", "bytecode_flow_max_edges")
        self.check(transforms, 9, 2, "bytecode_flow_loop_dispatch", "ByteCode_Flow 循环状态机（实验）")
        self.check(transforms, 10, 0, "bytecode_flow_block_seeds", "ByteCode_Flow 块级 Seed")
        self.entry(transforms, 10, "块 Seed 函数比例", "bytecode_flow_block_seed_ratio", col=2)
        self.entry(transforms, 11, "块 Seed 块数上限", "bytecode_flow_block_seed_max_blocks")
        self.check(transforms, 12, 0, "bytecode_flow_block_shuffle", "ByteCode_Flow 物理块乱序")
        self.entry(transforms, 12, "块乱序函数比例", "bytecode_flow_block_shuffle_ratio", col=2)
        self.entry(transforms, 13, "块乱序块数上限", "bytecode_flow_block_shuffle_max_blocks")

        gates = self.group(b, "门控、Opaque 与死块")
        self.check(gates, 0, 0, "bytecode_split_gates", "字节码拆分门")
        self.check(gates, 1, 0, "split_adaptive", "自适应拆分")
        self.check(gates, 2, 0, "loop_shadow_gates", "循环影子门（实验）")
        self.check(gates, 3, 0, "bytecode_opaque_predicates", "字节码 Opaque 谓词")
        self.check(gates, 4, 0, "real_block_reorder", "真实基本块重排（实验）")
        self.check(gates, 5, 0, "safe_dead_blocks", "跳过式死代码块")
        self.check(gates, 6, 0, "oparg_poison", "恒真跳转 + 非法 Opcode 毒块")
        self.check(gates, 6, 2, "bytecode_taken_jump_poison", "一键启用恒真跳转塞毒")
        self.entry(gates, 0, "拆分间隔", "bytecode_split_interval", col=2)
        self.entry(gates, 1, "拆分坏单元", "bytecode_split_bad_units", col=2)
        self.entry(gates, 2, "拆分 NOP 膨胀", "bytecode_split_nop_bloat", col=2)
        self.entry(gates, 3, "Opaque 间隔", "bytecode_opaque_interval", col=2)
        self.entry(gates, 4, "Opaque 宽度", "bytecode_opaque_width", col=2)
        self.entry(gates, 5, "Opaque 上限", "bytecode_opaque_limit", col=2)
        self.entry(gates, 6, "安全死块间隔", "safe_dead_interval", col=2)
        self.entry(gates, 7, "安全死块宽度", "safe_dead_width")
        self.entry(gates, 7, "安全死块上限", "safe_dead_limit", col=2)
        self.entry(gates, 8, "重排上限", "real_block_reorder_limit")
        self.check(gates, 9, 0, "bytecode_decoy_islands", "验证型诱饵指令岛")
        self.entry(gates, 9, "选中函数比例", "bytecode_decoy_island_ratio", col=2)
        self.entry(gates, 10, "单函数岛上限", "bytecode_decoy_island_limit")
        self.entry(gates, 10, "单岛操作上限", "bytecode_decoy_island_width", col=2)
        self.entry(gates, 11, "体积增长上限(%)", "bytecode_decoy_island_growth")

    def _loader_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="加载器")
        b = tab.body
        defaults = {
            "loader_junk": "", "trampoline_layers": "", "decoy_opcode_rows": "",
            "fake_ref_layers": "", "loader_decoy_tuples": 3, "outer_decompiler_baits": 0, "import_facade_layer": True,
            "anti_debug": False,
            "experimental_anti_debug": False,
            "api_decoy_refs": 32, "fake_mcs_tables": 3, "opcode_replacement": False,
            "runtime_opcode_layer": False,
            "per_code_runtime_opcode": False, "runtime_opcode_decoys": 128,
            "opcode_exclude": "", "inner_opcode_tunnel": False, "opcode_runtime": "std",
            "opcode_restore_noise": 12,
            "reflection_metadata_decoy": True, "module_registry_protection": True,
            "outer_closure_vault": True, "outer_dynamic_method": True,
            "outer_dynamic_class": True, "outer_callable_proxy": True,
            "outer_frame_namespace": True, "outer_generator_stages": True,
            "outer_exception_state": True, "outer_no_sys_import": True,
            "outer_tuple_gateway": True, "outer_closure_index_mirage": True,
            "outer_generator_frame_mirage": True,
            "outer_method_descriptor_mirage": True,
            "outer_defaults_dict_doppelganger": True,
        }
        for k, v in defaults.items():
            self.v(k, v)
        outer = self.group(b, "外层加载器")
        self.entry(outer, 0, "加载器垃圾代码", "loader_junk")
        self.entry(outer, 0, "蹦床层数", "trampoline_layers", col=2)
        self.entry(outer, 1, "伪 Opcode 行", "decoy_opcode_rows")
        self.entry(outer, 1, "伪引用层数", "fake_ref_layers", col=2)
        self.entry(outer, 2, "加载器伪 Tuple", "loader_decoy_tuples")
        self.entry(outer, 2, "API 伪引用", "api_decoy_refs", col=2)
        self.entry(outer, 3, "外层反编译器诱饵", "outer_decompiler_baits")
        self.entry(outer, 3, "伪 MCS 映射表", "fake_mcs_tables", col=2)
        self.check(outer, 4, 0, "import_facade_layer", "假模块 ImportError 门面")
        self.check(outer, 4, 2, "reflection_metadata_decoy", "反射元数据诱饵")
        self.check(outer, 5, 0, "module_registry_protection", "sys.modules 注册表保护")
        self.check(outer, 6, 0, "anti_debug", "网易原生 AntiDebugger（_chacha + UUID）")
        self.check(outer, 6, 2, "experimental_anti_debug", "实验性 Trace/Timing AntiDebug")

        weird = self.group(b, "外层动态执行与痕迹隐藏")
        self.check(weird, 0, 0, "outer_closure_vault", "闭包密钥/入口保险库")
        self.check(weird, 0, 2, "outer_dynamic_method", "运行时绑定调用方法")
        self.check(weird, 1, 0, "outer_dynamic_class", "使用 type() 动态构造类")
        self.check(weird, 1, 2, "outer_callable_proxy", "__call__ 调用代理")
        self.check(weird, 2, 0, "outer_frame_namespace", "生成器 Frame 获取命名空间")
        self.check(weird, 2, 2, "outer_generator_stages", "挂起生成器分阶段执行")
        self.check(weird, 3, 0, "outer_exception_state", "类型异常状态机")
        self.check(weird, 3, 2, "outer_no_sys_import", "外层禁止显式导入 sys")
        self.check(weird, 4, 0, "outer_tuple_gateway", "真实 .0/.1 元组参数网关")
        self.check(weird, 4, 2, "outer_closure_index_mirage", "闭包索引镜像")
        self.check(weird, 5, 0, "outer_generator_frame_mirage", "三生成器 Frame 镜像")
        self.check(weird, 5, 2, "outer_method_descriptor_mirage", "三重 Method/Descriptor 镜像")
        self.check(weird, 6, 0, "outer_defaults_dict_doppelganger", "Defaults/Function Dict 双重伪装")

        opcode = self.group(b, "运行时 Opcode 与 Tunnel")
        self.check(opcode, 0, 0, "opcode_replacement", "启用 Opcode 替换（总开关）")
        self.check(opcode, 1, 0, "runtime_opcode_layer", "运行时随机 Opcode 层")
        self.check(opcode, 2, 0, "per_code_runtime_opcode", "每个 Code 独立 Opcode")
        self.check(opcode, 3, 0, "inner_opcode_tunnel", "内部 Opcode Tunnel")
        self.entry(opcode, 1, "运行时映射诱饵", "runtime_opcode_decoys", col=2)
        self.entry(opcode, 2, "关闭 Opcode 的文件", "opcode_exclude", col=2, width=34)
        self.combo(opcode, 3, "Opcode 运行环境", "opcode_runtime", ["std", "mcs"], col=2)
        self.entry(opcode, 4, "恢复过程噪音", "opcode_restore_noise")

    def _advanced_tab(self, notebook):
        tab = ScrollFrame(notebook)
        notebook.add(tab, text="高级与危险项")
        b = tab.body
        defaults = {
            "metadata_poison": True, "metadata_binary": True, "metadata_name_poison": True,
            "adaptive_strength": False, "adaptive_max_scale": 4,
            "taunt_text": "ShitArmor_DEOBF", "taunt_inner_consts": 8, "taunt_outer_refs": 24,
            "dead_bad_bytecode": 1, "dead_bad_units": 2, "dead_nop_bloat": 24,
            "dead_stop_bloat": 12, "dead_arg_poison": 2, "dead_exception_poison": 1,
            "dead_call_poison": 1, "fake_code_objects": 2, "fake_code_nop_bloat": 24,
            "fake_code_stop_bloat": 12, "ghost_names": 24,
        }
        for k, v in defaults.items():
            self.v(k, v)
        meta = self.group(b, "元数据与自适应强度")
        self.check(meta, 0, 0, "metadata_poison", "元数据毒化")
        self.check(meta, 1, 0, "metadata_binary", "二进制元数据标签")
        self.check(meta, 2, 0, "metadata_name_poison", "名称元数据毒化")
        self.check(meta, 3, 0, "adaptive_strength", "按文件规模自适应增强")
        self.entry(meta, 3, "最大缩放倍数", "adaptive_max_scale", col=2)
        taunt = self.group(b, "嘲讽文本")
        self.entry(taunt, 0, "文本", "taunt_text", width=52)
        self.entry(taunt, 1, "内部常量数量", "taunt_inner_consts")
        self.entry(taunt, 1, "外部引用数量", "taunt_outer_refs", col=2)
        bad = self.group(b, "不可达坏字节码（高风险）")
        self.entry(bad, 0, "坏字节码块数", "dead_bad_bytecode")
        self.entry(bad, 0, "坏指令单元", "dead_bad_units", col=2)
        self.entry(bad, 1, "死 NOP 膨胀", "dead_nop_bloat")
        self.entry(bad, 1, "死 STOP_CODE 膨胀", "dead_stop_bloat", col=2)
        self.entry(bad, 2, "参数毒化", "dead_arg_poison")
        self.entry(bad, 2, "异常结构毒化", "dead_exception_poison", col=2)
        self.entry(bad, 3, "调用结构毒化", "dead_call_poison")
        fake = self.group(b, "伪 Code 对象与名称")
        self.entry(fake, 0, "伪 Code 对象数量", "fake_code_objects")
        self.entry(fake, 0, "伪 NOP 膨胀", "fake_code_nop_bloat", col=2)
        self.entry(fake, 1, "伪 STOP_CODE 膨胀", "fake_code_stop_bloat")
        self.entry(fake, 1, "幽灵名称数量", "ghost_names", col=2)

    def _actions(self, parent):
        box = ttk.LabelFrame(parent, text="运行", style="Card.TLabelframe")
        box.pack(fill="x")
        ttk.Button(box, text="开始混淆", command=self.run_obfuscator).pack(fill="x", pady=4)
        ttk.Button(box, text="预览执行命令", command=self.preview_command).pack(fill="x", pady=4)
        ttk.Button(box, text="打开输出位置", command=self.open_output).pack(fill="x", pady=4)
        ttk.Button(box, text="打开程序根目录", command=lambda: os.startfile(ROOT_DIR)).pack(fill="x", pady=4)
        cfg = ttk.LabelFrame(parent, text="配置", style="Card.TLabelframe")
        cfg.pack(fill="x", pady=(12, 0))
        ttk.Button(cfg, text="载入 UI JSON", command=self.load_ui_config).pack(fill="x", pady=4)
        ttk.Button(cfg, text="保存 UI JSON", command=self.save_ui_config).pack(fill="x", pady=4)
        ttk.Button(cfg, text="导入混淆器 YML", command=self.load_obf_config).pack(fill="x", pady=4)
        ttk.Button(cfg, text="导出混淆器 YML", command=self.export_obf_config).pack(fill="x", pady=4)
        ttk.Button(cfg, text="立即写入运行配置", command=self.write_run_config).pack(fill="x", pady=4)
        info = ttk.LabelFrame(parent, text="运行环境", style="Card.TLabelframe")
        info.pack(fill="both", expand=True, pady=(12, 0))
        self.env_text = tk.Text(info, height=8, wrap="word", relief="flat")
        self.env_text.pack(fill="both", expand=True)

    def _log_panel(self, parent):
        box = ttk.LabelFrame(parent, text="运行日志", style="Card.TLabelframe")
        box.pack(fill="both", pady=(10, 0))
        self.log = tk.Text(box, height=10, wrap="word")
        self.log.pack(fill="both", expand=True)

    def pick_input(self):
        path = filedialog.askdirectory(initialdir=ROOT_DIR) if self.vars["folder"].get() else filedialog.askopenfilename(initialdir=ROOT_DIR, filetypes=[("Python", "*.py"), ("All", "*.*")])
        if path:
            self.vars["input"].set(path)

    def pick_output(self):
        if self.vars["folder"].get():
            path = filedialog.askdirectory(initialdir=ROOT_DIR)
        else:
            emit_pyc = bool(self.vars.get("emit_pyc") and self.vars["emit_pyc"].get())
            extension = ".pyc" if emit_pyc else ".py"
            pattern = "*.pyc" if emit_pyc else "*.py"
            path = filedialog.asksaveasfilename(
                initialdir=ROOT_DIR, defaultextension=extension,
                filetypes=[("Python", pattern), ("All", "*.*")])
        if path:
            self.vars["output"].set(path)

    def pick_deploy(self):
        path = filedialog.askdirectory(initialdir=ROOT_DIR)
        if path:
            self.vars["deploy_target"].set(path)

    def _check_environment(self):
        lines = [
            "程序目录：" + ROOT_DIR,
            "混淆器 EXE：" + (find_obfuscator_exe() or "未找到"),
            "混淆器源码：" + ("可用" if (os.path.isfile(OBFUSCATOR_MODULE) or
                                      os.path.isfile(OBFUSCATOR)) else "未找到"),
            "Logo：" + ("可用" if os.path.exists(LOGO_PATH) else "未找到"),
            "运行策略：优先使用同目录 CLI EXE，否则调用 Python 3 MCP_Armor_Src",
        ]
        self.env_text.delete("1.0", "end")
        self.env_text.insert("end", "\n".join(lines))

    def append_log(self, text):
        if text:
            self.log.insert("end", text + "\n")
            self.log.see("end")

    def split_patterns(self, value):
        return [p.strip() for p in str(value).replace("\n", ";").split(";") if p.strip()]

    def typed_value(self, name):
        value = self.vars[name].get()
        if isinstance(value, str):
            text = value.strip()
            if text == "" or text.lower() in ("none", "null", "~"):
                return None
            if text.lstrip("-").isdigit():
                try:
                    return int(text)
                except ValueError:
                    return text
            return text
        return value

    def current_config(self):
        return {name: var.get() for name, var in self.vars.items()}

    def build_obf_config(self):
        cfg = {}
        for name in self.vars:
            value = self.typed_value(name)
            if value is not None:
                cfg[name] = value
        cfg["input"] = self.vars["input"].get()
        cfg["output"] = self.vars["output"].get()
        # Source compliance is a mandatory pipeline stage in both UIs.  The
        # full UI does not expose a bypass checkbox; projects may still use
        # the documented root marker when they intentionally need one.
        cfg["static_check"] = True
        cfg["source_only"] = self.split_patterns(self.vars["source_only"].get())
        cfg["ast_exclude"] = self.split_patterns(self.vars["ast_exclude"].get())
        cfg["source_vm_include"] = self.split_patterns(self.vars["source_vm_include"].get())
        cfg["source_vm_exclude"] = self.split_patterns(self.vars["source_vm_exclude"].get())
        cfg["source_hot_pattern"] = self.split_patterns(
            self.vars["source_hot_pattern"].get())
        cfg["source_reference_obf_exclude"] = self.split_patterns(
            self.vars["source_reference_obf_exclude"].get())
        cfg["source_module_rename_exclude"] = self.split_patterns(
            self.vars["source_module_rename_exclude"].get())
        cfg["lazy_capsule_include"] = self.split_patterns(self.vars["lazy_capsule_include"].get())
        cfg["lazy_capsule_exclude"] = self.split_patterns(self.vars["lazy_capsule_exclude"].get())
        cfg["include"] = self.split_patterns(self.vars["include"].get())
        exclude = self.split_patterns(self.vars["exclude"].get())
        exclude.extend(self.split_patterns(self.vars["plain_copy"].get()))
        cfg["exclude"] = exclude
        cfg["opcode_exclude"] = self.split_patterns(self.vars["opcode_exclude"].get())
        cfg["no_bytecode_obf"] = bool(self.vars["no_bytecode_obf"].get())
        cfg.pop("disable_ast", None)
        if bool(self.vars["disable_ast"].get()):
            for name, var in self.vars.items():
                if name.startswith("source_") and isinstance(var, tk.BooleanVar):
                    cfg[name] = False
            cfg["control_flow_flatten"] = False
        return cfg

    def make_obf_yml(self):
        cfg = self.build_obf_config()
        lines = ["# generated by MCP_Armor_UI.app"]
        for key in sorted(cfg.keys()):
            value = cfg[key]
            if isinstance(value, list):
                lines.append("%s:" % key)
                if value:
                    for item in value:
                        lines.append("  - %s" % yaml_scalar(item))
                else:
                    lines.append("  []")
            else:
                lines.append("%s: %s" % (key, yaml_scalar(value)))
        return "\n".join(lines) + "\n"

    def write_run_config(self):
        write_text(RUN_CONFIG, self.make_obf_yml())
        self.append_log("已写入运行配置：" + RUN_CONFIG)

    def build_command(self, redirect=False):
        self.write_run_config()
        argv = self.build_argv()
        cmd = format_command(argv)
        if redirect:
            cmd += " > " + shell_quote(RUN_LOG) + " 2>&1"
        return cmd

    def build_argv(self):
        exe = find_obfuscator_exe()
        if exe:
            return [exe, "--config", RUN_CONFIG]
        if FROZEN and ARGV_IS_EXE:
            return [os.path.abspath(sys.argv[0]), "--mcparmor-cli",
                    "--config", RUN_CONFIG]
        # Source-checkout fallback: run the package host directly.  The
        # repository no longer ships a root-level main.py and invoking the
        # Python-2 launcher here made the UI report a missing executable.
        if os.path.isfile(OBFUSCATOR_MODULE):
            return [sys.executable, "-m", "MCP_Armor_Src",
                    "--config", RUN_CONFIG]
        return [sys.executable, OBFUSCATOR, "--config", RUN_CONFIG]

    def build_cwd(self):
        return find_obfuscator_cwd()

    def preview_command(self):
        self.append_log("$ " + self.build_command(False))

    def run_obfuscator(self):
        if self.running:
            messagebox.showinfo(APP_TITLE, "混淆器正在运行，请等待当前任务完成。")
            return
        if (not FROZEN and not find_obfuscator_exe()
                and not os.path.isfile(OBFUSCATOR_MODULE)
                and not os.path.isfile(OBFUSCATOR)):
            messagebox.showerror(
                APP_TITLE,
                "未找到混淆器 CLI 或 MCP_Armor_Src 包入口。\n"
                "请将 01_MCPArmor_CLI.exe 放在 UI 同目录，或从项目根目录运行。")
            return
        self.write_run_config()
        argv = self.build_argv()
        cwd = self.build_cwd()
        self.append_log("$ " + format_command(argv))
        self.append_log("工作目录：" + cwd)
        self.status.set("正在混淆……")
        self.running = True
        threading.Thread(target=self._run_worker, args=(argv, cwd), daemon=True).start()

    def _decode_output(self, data):
        if not data:
            return ""
        for encoding in ("utf-8", "mbcs", "gbk"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                pass
        return data.decode("utf-8", "replace")

    def _run_worker(self, argv, cwd):
        started = time.time()
        output = ""
        code = 1
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            data = proc.communicate()[0]
            code = proc.returncode
            output = self._decode_output(data)
        except Exception as exc:
            output = "%s: %s" % (exc.__class__.__name__, exc)
        try:
            write_text(RUN_LOG, output)
        except Exception:
            pass
        elapsed = time.time() - started
        self.after(0, lambda: self._run_done(code, elapsed))

    def _run_done(self, code, elapsed):
        self.running = False
        if os.path.exists(RUN_LOG):
            self.append_log(read_text(RUN_LOG).strip())
        self.append_log("退出码=%s，用时=%.1f 秒" % (code, elapsed))
        self.status.set("完成" if code == 0 else "失败")

    def open_output(self):
        path = self.vars["output"].get().strip()
        if path and os.path.exists(path):
            os.startfile(path)
        else:
            messagebox.showinfo(APP_TITLE, "输出路径尚不存在，请先执行混淆。")

    def apply_config(self, data):
        for name, value in data.items():
            if name in ("include", "exclude", "plain_copy", "source_only", "ast_exclude", "opcode_exclude", "source_vm_include", "source_vm_exclude", "source_hot_pattern", "source_reference_obf_exclude", "source_module_rename_exclude", "lazy_capsule_include", "lazy_capsule_exclude") and isinstance(value, list):
                value = ";".join(str(x) for x in value)
            if name in self.vars:
                self.vars[name].set(value)

    def load_ui_config(self):
        path = filedialog.askopenfilename(initialdir=ROOT_DIR, filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self.apply_config(json.load(fh))
            self.append_log("已载入 UI 配置：" + path)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))

    def save_ui_config(self):
        path = filedialog.asksaveasfilename(initialdir=ROOT_DIR, defaultextension=".json", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        write_text(path, json.dumps(self.current_config(), ensure_ascii=False, indent=2))
        self.append_log("已保存 UI 配置：" + path)

    def load_obf_config(self):
        path = filedialog.askopenfilename(initialdir=ROOT_DIR, filetypes=[("YAML 配置", "*.yml *.yaml"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            self.apply_config(flatten_config(read_simple_yaml(path)))
            self.append_log("已导入混淆器配置：" + path)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))

    def export_obf_config(self):
        path = filedialog.asksaveasfilename(initialdir=ROOT_DIR, defaultextension=".yml", filetypes=[("YAML", "*.yml"), ("All", "*.*")])
        if not path:
            return
        write_text(path, self.make_obf_yml())
        self.append_log("已导出混淆器配置：" + path)


def _license_failure_message(status):
    if status.reason == "license_expired":
        title = "授权已到期，请续费后重新启动。"
    elif status.reason == "hwid_not_authorized":
        title = "当前设备未授权，请提交下方 HWID 获取授权。"
    elif status.reason.startswith("time_server_unavailable:"):
        title = "淘宝时间 API 不可用，暂时无法验证授权。"
    elif status.reason.startswith("license_server_unavailable:"):
        title = "Gitee 授权服务器不可用，请检查网络。"
    else:
        title = "HWID 授权验证失败：%s" % status.reason
    rows = [title, "", "HWID：%s" % status.code]
    if status.expires:
        rows.append("到期时间：%s" % status.expires)
    rows.extend(("", "HWID 已复制到剪贴板。"))
    return "\n".join(rows)


def _show_license_failure(status):
    root = tk.Tk()
    root.withdraw()
    try:
        root.clipboard_clear()
        root.clipboard_append(status.code)
        root.update()
    except tk.TclError:
        pass
    messagebox.showerror(APP_TITLE, _license_failure_message(status), parent=root)
    root.destroy()


def main():
    if not os.path.isdir(STATE_DIR):
        os.makedirs(STATE_DIR)
    license_status = validate_license()
    if not license_status.valid:
        _show_license_failure(license_status)
        return 3
    app = ObfUI()
    app.mainloop()


if __name__ == "__main__":
    main()
