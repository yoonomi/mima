"""
图形界面主程序 - Tkinter 桌面可视化
提供加密、解密、密钥管理、性能测试(含Matplotlib图表)、完整性校验功能
"""

import os
import sys

# 强制 Matplotlib 使用 TkAgg 后端，必须在导入 matplotlib 之前设置
os.environ.setdefault('MPLBACKEND', 'TkAgg')

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
from threading import Thread
from datetime import datetime

# 确保项目根目录在路径中（兼容 PyInstaller 打包环境）
if getattr(sys, 'frozen', False):
    # PyInstaller 打包后，模块在 _internal 目录下
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import TEST_DATA_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, REPORTS_DIR
from core.aes_crypto import get_supported_modes as aes_modes, generate_key as aes_gen_key
from core.des_crypto import get_supported_modes as des_modes, generate_key as des_gen_key
from core.key_manager import KeyManager
from core.password_checker import check_password_strength, generate_strong_password
from file_system.file_encrypt import encrypt_single_file
from file_system.file_decrypt import decrypt_single_file
from file_system.file_utils import format_file_size, list_files
from integrity.file_hash import compute_file_hashes
from integrity.hash_compare import compare_files
from integrity.integrity_report import generate_integrity_report
from performance.aes_benchmark import run_aes_benchmark
from performance.des_benchmark import run_des_benchmark
from performance.performance_report import generate_performance_report
from logs.logger import get_recent_logs


class SecureAESGUI:
    """Secure AES 系统图形界面主窗口"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure AES 加密系统 - v1.0")
        self.root.geometry("900x650")
        self.root.minsize(800, 580)

        # 设置图标（如果有）
        try:
            self.root.iconbitmap(default='')
        except Exception:
            pass

        # 颜色方案
        self.colors = {
            'bg': '#f0f0f0',
            'header': '#2c3e50',
            'accent': '#3498db',
            'success': '#27ae60',
            'danger': '#e74c3c',
            'warning': '#f39c12',
        }
        self.root.configure(bg=self.colors['bg'])

        # 密钥管理器
        self.km = KeyManager()

        # 当前使用的密钥
        self.current_key = None
        self.current_key_name = None
        self.current_algorithm = 'AES'
        self.current_mode = 'CBC'

        # 操作状态锁，防止重复点击
        self._encrypting = False
        self._decrypting = False

        # 构建界面
        self._build_header()
        self._build_notebook()
        self._build_status_bar()

        # 退出确认
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─── 标题栏 ───

    def _build_header(self):
        """构建标题栏"""
        header = tk.Frame(self.root, bg=self.colors['header'], height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        title_font = Font(family="Microsoft YaHei", size=16, weight="bold")
        tk.Label(header, text="Secure AES 加密系统",
                 fg='white', bg=self.colors['header'],
                 font=title_font).pack(side=tk.LEFT, padx=20, pady=12)

        sub_font = Font(family="Microsoft YaHei", size=9)
        tk.Label(header, text="2023337621104 金科丞 | 基于对称密码体系的数据加密解密",
                 fg='#bdc3c7', bg=self.colors['header'],
                 font=sub_font).pack(side=tk.RIGHT, padx=20, pady=15)

        # 查看日志按钮
        log_btn = tk.Button(header, text="📋 日志", font=('Microsoft YaHei', 9),
                            bg=self.colors['header'], fg='#bdc3c7',
                            activebackground='#34495e', activeforeground='white',
                            bd=0, cursor='hand2',
                            command=self._show_logs)
        log_btn.pack(side=tk.RIGHT, padx=(0, 10), pady=12)

    # ─── 选项卡 ───

    def _build_notebook(self):
        """构建选项卡面板"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 0))

        # 创建各选项卡
        self._create_encrypt_tab()
        self._create_decrypt_tab()
        self._create_key_tab()
        self._create_performance_tab()
        self._create_integrity_tab()

        # 切换选项卡时自动刷新
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_change)

    # ═══════════════════════════════════════
    #  选项卡1：文件加密
    # ═══════════════════════════════════════

    def _create_encrypt_tab(self):
        """创建加密选项卡"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 文件加密 ")

        # 左右分栏
        left = ttk.LabelFrame(tab, text="加密设置", padding=10)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right = ttk.LabelFrame(tab, text="加密结果", padding=10)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ── 左侧：设置 ──
        row = 0
        ttk.Label(left, text="选择文件:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.enc_file_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.enc_file_var, width=35).grid(row=row, column=1, padx=5)
        ttk.Button(left, text="浏览", command=self._browse_encrypt_file).grid(row=row, column=2)
        row += 1

        ttk.Label(left, text="加密算法:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.enc_algo_var = tk.StringVar(value='AES')
        algo_frame = ttk.Frame(left)
        algo_frame.grid(row=row, column=1, columnspan=2, sticky=tk.W)
        ttk.Radiobutton(algo_frame, text="AES", variable=self.enc_algo_var,
                        value='AES', command=self._on_algo_change).pack(side=tk.LEFT)
        ttk.Radiobutton(algo_frame, text="DES", variable=self.enc_algo_var,
                        value='DES', command=self._on_algo_change).pack(side=tk.LEFT, padx=10)
        row += 1

        ttk.Label(left, text="加密模式:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.enc_mode_var = tk.StringVar(value='CBC')
        self.enc_mode_combo = ttk.Combobox(left, textvariable=self.enc_mode_var,
                                           values=aes_modes(), state='readonly', width=15)
        self.enc_mode_combo.grid(row=row, column=1, sticky=tk.W, padx=5)
        row += 1

        ttk.Label(left, text="生成的密钥:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.enc_key_var = tk.StringVar(value='(每次加密自动生成新密钥)')
        ttk.Label(left, textvariable=self.enc_key_var, foreground='#555').grid(
            row=row, column=1, columnspan=2, sticky=tk.W, padx=5)
        row += 1

        self.enc_keysize_label = ttk.Label(left, text="密钥长度:")
        self.enc_keysize_label.grid(row=row, column=0, sticky=tk.W, pady=4)
        self.enc_keysize_var = tk.StringVar(value='256')
        self.enc_ks_frame = ttk.Frame(left)
        self.enc_ks_frame.grid(row=row, column=1, columnspan=2, sticky=tk.W)
        for ks in ['128', '192', '256']:
            ttk.Radiobutton(self.enc_ks_frame, text=ks+'位', variable=self.enc_keysize_var,
                            value=ks).pack(side=tk.LEFT)
        row += 1

        self.encrypt_btn = ttk.Button(left, text="开始加密", command=self._do_encrypt,
                                       style='Accent.TButton')
        self.encrypt_btn.grid(row=row, column=0, columnspan=3, pady=15)

        # ── 右侧：结果 ──
        self.enc_result_text = scrolledtext.ScrolledText(right, width=45, height=22,
                                                         font=('Consolas', 9))
        self.enc_result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_encrypt_file(self):
        """浏览要加密的文件"""
        path = filedialog.askopenfilename(title="选择要加密的文件")
        if path:
            self.enc_file_var.set(path)

    def _on_algo_change(self):
        """算法切换时更新模式选项和密钥长度"""
        algo = self.enc_algo_var.get()
        modes = aes_modes() if algo == 'AES' else des_modes()
        self.enc_mode_combo['values'] = modes
        self.enc_mode_var.set('CBC' if 'CBC' in modes else modes[0])

        # 选择 DES 时隐藏密钥长度选项（DES 固定 56 位）
        if algo == 'DES':
            self.enc_keysize_label.grid_remove()
            self.enc_ks_frame.grid_remove()
        else:
            self.enc_keysize_label.grid()
            self.enc_ks_frame.grid()

    def _do_encrypt(self):
        """执行加密操作"""
        if getattr(self, '_encrypting', False):
            messagebox.showwarning("提示", "正在加密中，请等待当前操作完成")
            return

        filepath = self.enc_file_var.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("错误", "请选择有效的文件")
            return

        algo = self.enc_algo_var.get()
        mode = self.enc_mode_var.get()
        key_size = int(self.enc_keysize_var.get()) if algo == 'AES' else 56

        self._encrypting = True
        self.encrypt_btn.configure(state='disabled')
        self.enc_result_text.delete(1.0, tk.END)
        self.enc_result_text.insert(tk.END, "加密中，请稍候...\n")

        # 生成或使用已有密钥
        if algo == 'AES':
            key_info = self.km.generate_aes_key(key_size)
            key = self.km.get_key(key_info['name'])
            self.current_key_name = key_info['name']
        else:
            key_info = self.km.generate_des_key()
            key = self.km.get_key(key_info['name'])
            self.current_key_name = key_info['name']

        self.enc_key_var.set(self.current_key_name)

        def task():
            try:
                result = encrypt_single_file(filepath, algo, mode, key, key_size=key_size)
                self.root.after(0, lambda: self._show_encrypt_result(result))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda e=err_msg: messagebox.showerror("加密失败", e))
                self.root.after(0, lambda e=err_msg: self.enc_result_text.insert(
                    tk.END, f"\n[✗] 加密失败: {e}\n"))
            finally:
                self.root.after(0, lambda: self._reset_encrypt_state())

        Thread(target=task, daemon=True).start()

    def _reset_encrypt_state(self):
        """重置加密状态"""
        self._encrypting = False
        try:
            self.encrypt_btn.configure(state='normal')
        except Exception:
            pass

    def _show_encrypt_result(self, result):
        """显示加密结果"""
        self.enc_result_text.delete(1.0, tk.END)
        self.enc_result_text.insert(tk.END, "=" * 40 + "\n")
        self.enc_result_text.insert(tk.END, "  加密成功 ✓\n")
        self.enc_result_text.insert(tk.END, "=" * 40 + "\n\n")
        self.enc_result_text.insert(tk.END, f"原文件:   {os.path.basename(result['input_file'])}\n")
        self.enc_result_text.insert(tk.END, f"原大小:   {result['original_size_fmt']}\n")
        self.enc_result_text.insert(tk.END, f"加密后:   {os.path.basename(result['output_file'])}\n")
        self.enc_result_text.insert(tk.END, f"加密大小: {result['encrypted_size_fmt']}\n")
        self.enc_result_text.insert(tk.END, f"保存位置: {os.path.dirname(result['output_file'])}\n")
        self.enc_result_text.insert(tk.END, f"算法:     {result['algorithm']}\n")
        self.enc_result_text.insert(tk.END, f"模式:     {result['mode']}\n")
        self.enc_result_text.insert(tk.END, f"密钥:     {self.current_key_name}\n")

        # 加密完成后自动刷新解密密钥列表，并选中刚生成的密钥
        self._refresh_dec_keys()
        if self.current_key_name:
            self.dec_key_var.set(self.current_key_name)

    # ═══════════════════════════════════════
    #  选项卡2：文件解密
    # ═══════════════════════════════════════

    def _create_decrypt_tab(self):
        """创建解密选项卡"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 文件解密 ")

        left = ttk.LabelFrame(tab, text="解密设置", padding=10)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right = ttk.LabelFrame(tab, text="解密结果", padding=10)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 左侧
        row = 0
        ttk.Label(left, text="加密文件:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.dec_file_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.dec_file_var, width=35).grid(row=row, column=1, padx=5)
        ttk.Button(left, text="浏览", command=self._browse_decrypt_file).grid(row=row, column=2)
        row += 1

        ttk.Label(left, text="解密算法:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.dec_algo_var = tk.StringVar(value='AES')
        ttk.Combobox(left, textvariable=self.dec_algo_var,
                     values=['AES', 'DES'], state='readonly', width=15).grid(
            row=row, column=1, sticky=tk.W, padx=5)
        row += 1

        ttk.Label(left, text="加密模式:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.dec_mode_var = tk.StringVar(value='CBC')
        self.dec_mode_combo = ttk.Combobox(left, textvariable=self.dec_mode_var,
                                           values=aes_modes(), state='readonly', width=15)
        self.dec_mode_combo.grid(row=row, column=1, sticky=tk.W, padx=5)
        row += 1

        def on_dec_algo_change(*args):
            algo = self.dec_algo_var.get()
            modes = aes_modes() if algo == 'AES' else des_modes()
            self.dec_mode_combo['values'] = modes
            self.dec_mode_var.set('CBC' if 'CBC' in modes else modes[0])
        self.dec_algo_var.trace_add('write', on_dec_algo_change)

        ttk.Label(left, text="选择密钥:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.dec_key_var = tk.StringVar()
        key_frame = ttk.Frame(left)
        key_frame.grid(row=row, column=1, columnspan=2, sticky=tk.W, padx=5)
        self.dec_key_combo = ttk.Combobox(key_frame, textvariable=self.dec_key_var,
                                          values=self._get_key_names(), state='readonly', width=27)
        self.dec_key_combo.pack(side=tk.LEFT)
        ttk.Button(key_frame, text="🔄", width=3,
                   command=self._refresh_dec_keys).pack(side=tk.LEFT, padx=3)
        row += 1

        self.decrypt_btn = ttk.Button(left, text="开始解密", command=self._do_decrypt,
                                       style='Accent.TButton')
        self.decrypt_btn.grid(row=row, column=0, columnspan=3, pady=15)

        # 右侧
        self.dec_result_text = scrolledtext.ScrolledText(right, width=45, height=22,
                                                         font=('Consolas', 9))
        self.dec_result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_decrypt_file(self):
        path = filedialog.askopenfilename(title="选择要解密的文件")
        if path:
            self.dec_file_var.set(path)

    def _get_key_names(self):
        keys = self.km.list_keys()
        return list(keys.keys()) if keys else ['(无可用密钥)']

    def _refresh_dec_keys(self):
        """刷新解密界面的密钥下拉列表"""
        keys = self._get_key_names()
        self.dec_key_combo['values'] = keys
        if keys and keys[0] != '(无可用密钥)':
            self.dec_key_var.set(keys[-1])  # 默认选中最新密钥
        else:
            self.dec_key_var.set('')

    def _on_tab_change(self, event=None):
        """切换选项卡时自动刷新"""
        try:
            tab_id = self.notebook.select()
            tab_text = self.notebook.tab(tab_id, 'text')
            if '解密' in tab_text:
                self._refresh_dec_keys()
        except Exception:
            pass

    def _do_decrypt(self):
        # 防止重复点击
        if getattr(self, '_decrypting', False):
            messagebox.showwarning("提示", "正在解密中，请等待当前操作完成")
            return

        filepath = self.dec_file_var.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("错误", "请选择有效的加密文件")
            return

        algo = self.dec_algo_var.get()
        mode = self.dec_mode_var.get()
        key_name = self.dec_key_var.get()

        if not key_name or key_name == '(无可用密钥)':
            messagebox.showerror("错误", "请选择有效的密钥")
            return

        key = self.km.get_key(key_name)
        if key is None:
            messagebox.showerror("错误", "密钥无效")
            return

        self._decrypting = True
        self.decrypt_btn.configure(state='disabled')
        self.dec_result_text.delete(1.0, tk.END)
        self.dec_result_text.insert(tk.END, "解密中，请稍候...\n")

        def task():
            try:
                result = decrypt_single_file(filepath, key, algo, mode)
                self.root.after(0, lambda: self._show_decrypt_result(result))
            except ValueError as e:
                err_msg = str(e)
                self.root.after(0, lambda e=err_msg, a=algo, m=mode: messagebox.showerror(
                    "解密失败",
                    f"密钥不正确或数据已损坏！\n\n"
                    f"可能原因：\n"
                    f"1. 选择的密钥与加密时使用的密钥不一致\n"
                    f"2. 加密模式不匹配（当前: {a}-{m}）\n"
                    f"3. 文件已被篡改\n\n"
                    f"详细错误: {e}"
                ))
                self.root.after(0, lambda: self.dec_result_text.insert(
                    tk.END, "\n[✗] 解密失败：密钥或模式不正确\n"))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda e=err_msg: messagebox.showerror(
                    "解密异常", f"解密过程发生异常:\n{e}"))
                self.root.after(0, lambda e=err_msg: self.dec_result_text.insert(
                    tk.END, f"\n[✗] 解密异常: {e}\n"))
            finally:
                self.root.after(0, lambda: self._reset_decrypt_state())

        Thread(target=task, daemon=True).start()

    def _reset_decrypt_state(self):
        """重置解密状态"""
        self._decrypting = False
        try:
            self.decrypt_btn.configure(state='normal')
        except Exception:
            pass

    def _show_decrypt_result(self, result):
        self.dec_result_text.delete(1.0, tk.END)
        self.dec_result_text.insert(tk.END, "=" * 40 + "\n")
        self.dec_result_text.insert(tk.END, "  解密成功 ✓\n")
        self.dec_result_text.insert(tk.END, "=" * 40 + "\n\n")
        self.dec_result_text.insert(tk.END, f"加密文件:  {os.path.basename(result['input_file'])}\n")
        self.dec_result_text.insert(tk.END, f"密文大小:  {result['encrypted_size_fmt']}\n")
        self.dec_result_text.insert(tk.END, f"解密文件:  {os.path.basename(result['output_file'])}\n")
        self.dec_result_text.insert(tk.END, f"解密大小:  {result['decrypted_size_fmt']}\n")
        self.dec_result_text.insert(tk.END, f"保存位置:  {os.path.dirname(result['output_file'])}\n")
        self.dec_result_text.insert(tk.END, f"算法:      {result['algorithm']}\n")
        self.dec_result_text.insert(tk.END, f"模式:      {result['mode']}\n")

    # ═══════════════════════════════════════
    #  选项卡3：密钥管理
    # ═══════════════════════════════════════

    def _create_key_tab(self):
        """创建密钥管理选项卡"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 密钥管理 ")

        # 上半：操作区
        op_frame = ttk.LabelFrame(tab, text="密钥操作", padding=10)
        op_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(op_frame, text="生成AES-128密钥", command=lambda: self._gen_key('AES', 128)).pack(side=tk.LEFT, padx=5)
        ttk.Button(op_frame, text="生成AES-256密钥", command=lambda: self._gen_key('AES', 256)).pack(side=tk.LEFT, padx=5)
        ttk.Button(op_frame, text="生成DES密钥", command=lambda: self._gen_key('DES', 56)).pack(side=tk.LEFT, padx=5)
        ttk.Button(op_frame, text="刷新列表", command=self._refresh_key_list).pack(side=tk.RIGHT, padx=5)

        # 下半：密钥列表
        list_frame = ttk.LabelFrame(tab, text="已保存密钥", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ('name', 'algorithm', 'key_size', 'created')
        self.key_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        self.key_tree.heading('name', text='密钥名称')
        self.key_tree.heading('algorithm', text='算法')
        self.key_tree.heading('key_size', text='密钥长度')
        self.key_tree.heading('created', text='创建时间')
        self.key_tree.column('name', width=200)
        self.key_tree.column('algorithm', width=80)
        self.key_tree.column('key_size', width=100)
        self.key_tree.column('created', width=160)
        self.key_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.key_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.key_tree.configure(yscrollcommand=scrollbar.set)

        btn_frame = ttk.Frame(list_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="删除选中密钥",
                   command=self._delete_selected_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="导出Base64",
                   command=self._export_key).pack(side=tk.LEFT, padx=5)

        self._refresh_key_list()

    def _gen_key(self, algo, key_size):
        try:
            if algo == 'AES':
                info = self.km.generate_aes_key(key_size)
            else:
                info = self.km.generate_des_key()
            messagebox.showinfo("成功", f"密钥已生成: {info['name']}")
            self._refresh_key_list()
            self._refresh_dec_keys()
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _refresh_key_list(self):
        for item in self.key_tree.get_children():
            self.key_tree.delete(item)
        keys = self.km.list_keys()
        for name, info in keys.items():
            self.key_tree.insert('', tk.END, values=(
                name, info['algorithm'], f"{info['key_size']}位", info['created']
            ))

    def _delete_selected_key(self):
        selected = self.key_tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先选择要删除的密钥")
            return
        name = self.key_tree.item(selected[0])['values'][0]
        if messagebox.askyesno("确认", f"确定删除密钥 '{name}' 吗？"):
            self.km.delete_key(name)
            self._refresh_key_list()

    def _export_key(self):
        selected = self.key_tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先选择要导出的密钥")
            return
        name = self.key_tree.item(selected[0])['values'][0]
        b64 = self.km.export_key(name)
        if b64:
            messagebox.showinfo("导出密钥", f"密钥 {name} 的Base64编码:\n\n{b64}")

    # ═══════════════════════════════════════
    #  选项卡4：性能测试 + Matplotlib图表
    # ═══════════════════════════════════════

    def _create_performance_tab(self):
        """创建性能测试选项卡（含Matplotlib图表）"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 性能测试 ")

        # 顶部控制区
        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(ctrl_frame, text="测试数据:").pack(side=tk.LEFT)
        self.perf_file_var = tk.StringVar()
        ttk.Entry(ctrl_frame, textvariable=self.perf_file_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="选择文件", command=self._browse_perf_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_frame, text="使用小文件", command=self._use_small_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_frame, text="开始测试", command=self._run_performance,
                   style='Accent.TButton').pack(side=tk.RIGHT, padx=5)

        # Matplotlib 图表区域
        self._init_matplotlib(tab)

        # 结果显示
        self.perf_result_text = scrolledtext.ScrolledText(tab, height=8, font=('Consolas', 9))
        self.perf_result_text.pack(fill=tk.BOTH, padx=5, pady=(0, 5))

    def _init_matplotlib(self, parent):
        """初始化 Matplotlib 图表"""
        try:
            import matplotlib
            matplotlib.use('TkAgg')  # 强制使用 TkAgg 后端，避免打包 PyQt5
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
            matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'DejaVu Sans']
            matplotlib.rcParams['axes.unicode_minus'] = False

            self.mpl_fig = Figure(figsize=(8, 3.8), dpi=100)
            self.mpl_fig.subplots_adjust(hspace=0.4, wspace=0.3)

            # 加密速度子图
            self.ax_enc = self.mpl_fig.add_subplot(121)
            # 解密速度子图
            self.ax_dec = self.mpl_fig.add_subplot(122)

            self.mpl_canvas = FigureCanvasTkAgg(self.mpl_fig, master=parent)
            self.mpl_canvas.get_tk_widget().pack(fill=tk.BOTH, padx=5, pady=5)

            # 初始空白图表
            self._draw_empty_chart()

        except ImportError:
            # Matplotlib未安装时显示提示
            frame = ttk.LabelFrame(parent, text="Matplotlib 图表")
            frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            ttk.Label(frame, text="需要安装 matplotlib:\npip install matplotlib",
                      foreground='red', font=('Microsoft YaHei', 12)).pack(expand=True)

            self.mpl_canvas = None

    def _draw_empty_chart(self):
        """绘制空白图表"""
        if not hasattr(self, 'mpl_canvas') or self.mpl_canvas is None:
            return
        self.ax_enc.clear()
        self.ax_dec.clear()
        self.ax_enc.set_title('加密速度 (MB/s) - 等待测试...')
        self.ax_dec.set_title('解密速度 (MB/s) - 等待测试...')
        self.ax_enc.bar([0], [0], color='#ddd')
        self.ax_dec.bar([0], [0], color='#ddd')
        self.mpl_canvas.draw()

    def _browse_perf_file(self):
        path = filedialog.askopenfilename(title="选择性能测试文件")
        if path:
            self.perf_file_var.set(path)

    def _use_small_file(self):
        small = os.path.join(TEST_DATA_DIR, 'small.txt')
        if os.path.exists(small):
            self.perf_file_var.set(small)
        else:
            messagebox.showwarning("提示", "测试文件不存在")

    def _run_performance(self):
        """运行性能测试并绘制图表"""
        filepath = self.perf_file_var.get()
        if filepath and os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                data = f.read()
        else:
            # 使用默认测试数据
            data = b'Secure AES Performance Test Data - ' * 1000

        self.perf_result_text.delete(1.0, tk.END)
        self.perf_result_text.insert(tk.END, f"测试数据大小: {format_file_size(len(data))}\n")
        self.perf_result_text.insert(tk.END, "正在测试，请稍候...\n")

        def task():
            try:
                # 运行测试
                aes_results = run_aes_benchmark(data, modes=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                                key_sizes=[256])
                des_results = run_des_benchmark(data, modes=['ECB', 'CBC'])

                self.root.after(0, lambda: self._update_perf_chart(aes_results, des_results, data))

                # 生成报告
                report = generate_performance_report(data)
                self.root.after(0, lambda: self._show_perf_result(aes_results, des_results, report))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("测试失败", str(e)))

        Thread(target=task, daemon=True).start()

    def _update_perf_chart(self, aes_results, des_results, data):
        """更新性能图表"""
        if not hasattr(self, 'mpl_canvas') or self.mpl_canvas is None:
            return

        import numpy as np
        from matplotlib.figure import Figure

        # 准备数据
        aes_modes_list = [r.mode for r in aes_results]
        aes_enc_speeds = [r.encrypt_speed for r in aes_results]
        aes_dec_speeds = [r.decrypt_speed for r in aes_results]
        des_modes_list = [r.mode for r in des_results]
        des_enc_speeds = [r.encrypt_speed for r in des_results]
        des_dec_speeds = [r.decrypt_speed for r in des_results]

        # 清空重绘
        self.ax_enc.clear()
        self.ax_dec.clear()

        x = np.arange(len(aes_modes_list + des_modes_list))
        labels = aes_modes_list + [f'DES-{m}' for m in des_modes_list]
        speeds_enc = aes_enc_speeds + des_enc_speeds
        speeds_dec = aes_dec_speeds + des_dec_speeds

        colors = ['#3498db'] * len(aes_modes_list) + ['#e67e22'] * len(des_modes_list)

        bars_enc = self.ax_enc.bar(x, speeds_enc, color=colors, width=0.6)
        self.ax_enc.set_xticks(x)
        self.ax_enc.set_xticklabels(labels, fontsize=8)
        self.ax_enc.set_title(f'AES-256 vs DES 加密速度对比\n(数据大小: {format_file_size(len(data))})',
                              fontsize=10, fontweight='bold')
        self.ax_enc.set_ylabel('速度 (MB/s)', fontsize=9)

        # 在柱上显示数值
        for bar, v in zip(bars_enc, speeds_enc):
            self.ax_enc.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                             f'{v:.1f}', ha='center', va='bottom', fontsize=7)

        bars_dec = self.ax_dec.bar(x, speeds_dec, color=colors, width=0.6)
        self.ax_dec.set_xticks(x)
        self.ax_dec.set_xticklabels(labels, fontsize=8)
        self.ax_dec.set_title('解密速度对比', fontsize=10, fontweight='bold')
        self.ax_dec.set_ylabel('速度 (MB/s)', fontsize=9)

        for bar, v in zip(bars_dec, speeds_dec):
            self.ax_dec.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                             f'{v:.1f}', ha='center', va='bottom', fontsize=7)

        # 图例
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#3498db', label='AES-256'),
            Patch(facecolor='#e67e22', label='DES'),
        ]
        self.ax_enc.legend(handles=legend_elements, loc='upper right', fontsize=8)
        self.ax_dec.legend(handles=legend_elements, loc='upper right', fontsize=8)

        self.mpl_fig.tight_layout()
        self.mpl_canvas.draw()

    def _show_perf_result(self, aes_results, des_results, report):
        """显示性能测试结果"""
        self.perf_result_text.delete(1.0, tk.END)
        self.perf_result_text.insert(tk.END, "=" * 50 + "\n")
        self.perf_result_text.insert(tk.END, "  性能测试完成 ✓\n")
        self.perf_result_text.insert(tk.END, "=" * 50 + "\n\n")

        self.perf_result_text.insert(tk.END, "AES-256 各模式加密速度:\n")
        for r in aes_results:
            self.perf_result_text.insert(tk.END,
                f"  {r.mode:4s}: 加密 {r.encrypt_speed:>8.2f} MB/s | "
                f"解密 {r.decrypt_speed:>8.2f} MB/s\n")

        self.perf_result_text.insert(tk.END, "\nDES 各模式加密速度:\n")
        for r in des_results:
            self.perf_result_text.insert(tk.END,
                f"  {r.mode:4s}: 加密 {r.encrypt_speed:>8.2f} MB/s | "
                f"解密 {r.decrypt_speed:>8.2f} MB/s\n")

        self.perf_result_text.insert(tk.END, f"\n报告已保存: {report}\n")

    # ═══════════════════════════════════════
    #  选项卡5：完整性校验
    # ═══════════════════════════════════════

    def _create_integrity_tab(self):
        """创建完整性校验选项卡"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 完整性校验 ")

        left = ttk.LabelFrame(tab, text="文件选择", padding=10)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right = ttk.LabelFrame(tab, text="校验结果", padding=10)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ── 左侧 ──
        row = 0
        ttk.Label(left, text="原始文件:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.int_orig_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.int_orig_var, width=30).grid(row=row, column=1, padx=5)
        ttk.Button(left, text="浏览", command=lambda: self._browse_int('orig')).grid(row=row, column=2)
        row += 1

        ttk.Label(left, text="解密文件:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self.int_dec_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.int_dec_var, width=30).grid(row=row, column=1, padx=5)
        ttk.Button(left, text="浏览", command=lambda: self._browse_int('dec')).grid(row=row, column=2)
        row += 1

        ttk.Separator(left, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=3,
                                                        sticky=tk.EW, pady=10)
        row += 1

        ttk.Button(left, text="计算单个文件哈希", command=self._calc_single_hash,
                   style='Accent.TButton').grid(row=row, column=0, columnspan=3, pady=5)
        row += 1
        ttk.Button(left, text="对比两个文件哈希", command=self._compare_hash,
                   style='Accent.TButton').grid(row=row, column=0, columnspan=3, pady=5)
        row += 1
        ttk.Button(left, text="生成完整性校验报告", command=self._gen_int_report).grid(
            row=row, column=0, columnspan=3, pady=5)

        # 右侧结果
        self.int_result_text = scrolledtext.ScrolledText(right, width=45, height=24,
                                                         font=('Consolas', 9))
        self.int_result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_int(self, target):
        path = filedialog.askopenfilename()
        if path:
            if target == 'orig':
                self.int_orig_var.set(path)
            else:
                self.int_dec_var.set(path)

    def _calc_single_hash(self):
        filepath = self.int_orig_var.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("错误", "请选择文件")
            return
        hashes = compute_file_hashes(filepath)
        if hashes:
            self.int_result_text.delete(1.0, tk.END)
            self.int_result_text.insert(tk.END, f"文件: {hashes['file_name']}\n")
            self.int_result_text.insert(tk.END, f"大小: {hashes['file_size_fmt']}\n\n")
            self.int_result_text.insert(tk.END, f"MD5:   {hashes['md5']}\n")
            self.int_result_text.insert(tk.END, f"SHA1:  {hashes['sha1']}\n")
            self.int_result_text.insert(tk.END, f"SHA256:{hashes['sha256']}\n")

    def _compare_hash(self):
        orig = self.int_orig_var.get()
        dec = self.int_dec_var.get()
        if not orig or not dec:
            messagebox.showerror("错误", "请选择原始文件和解密文件")
            return
        if not os.path.exists(orig) or not os.path.exists(dec):
            messagebox.showerror("错误", "文件不存在")
            return

        result = compare_files(orig, dec)
        self.int_result_text.delete(1.0, tk.END)
        self.int_result_text.insert(tk.END, "哈希对比结果:\n\n")
        for algo, data in result['algorithms'].items():
            status = "✓ 一致" if data['match'] else "✗ 不一致"
            self.int_result_text.insert(tk.END, f"{algo}: {status}\n")
            self.int_result_text.insert(tk.END, f"  原文件: {data['original_hash'][:20]}...\n")
            self.int_result_text.insert(tk.END, f"  解密后: {data['decrypted_hash'][:20]}...\n\n")

        if result['match']:
            self.int_result_text.insert(tk.END, "结论: ✓ 文件完整性校验通过\n")
        else:
            self.int_result_text.insert(tk.END, "结论: ✗ 文件完整性校验失败\n")

    def _gen_int_report(self):
        orig = self.int_orig_var.get()
        dec = self.int_dec_var.get()
        if not orig or not dec:
            messagebox.showerror("错误", "请选择原始文件和解密文件")
            return
        try:
            report = generate_integrity_report(orig, dec)
            messagebox.showinfo("成功", f"完整性校验报告已生成:\n{report}")
            with open(report, 'r', encoding='utf-8') as f:
                content = f.read()
            self.int_result_text.delete(1.0, tk.END)
            self.int_result_text.insert(tk.END, content[:2000])
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ─── 状态栏 ───

    def _build_status_bar(self):
        """构建底部状态栏"""
        status = tk.Frame(self.root, bg='#ecf0f1', height=28)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        status.pack_propagate(False)

        self.status_var = tk.StringVar(value="就绪 | 2023337621104 金科丞")
        tk.Label(status, textvariable=self.status_var,
                 bg='#ecf0f1', fg='#555', font=('Microsoft YaHei', 9)).pack(side=tk.LEFT, padx=12)

    # ─── 窗口关闭 ───

    # ─── 日志查看 ───

    def _show_logs(self):
        """弹出日志查看窗口"""
        log_win = tk.Toplevel(self.root)
        log_win.title("系统操作日志")
        log_win.geometry("700x450")
        log_win.minsize(500, 300)
        log_win.transient(self.root)

        header = tk.Frame(log_win, bg=self.colors['header'], height=40)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)
        tk.Label(header, text="系统操作日志", fg='white',
                 bg=self.colors['header'],
                 font=('Microsoft YaHei', 12, 'bold')).pack(side=tk.LEFT, padx=15, pady=8)

        text_area = scrolledtext.ScrolledText(log_win, font=('Consolas', 10),
                                              wrap=tk.WORD, bg='#1e1e1e', fg='#d4d4d4')
        text_area.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        btn_frame = tk.Frame(log_win)
        btn_frame.pack(fill=tk.X, padx=8, pady=(0, 8))

        def refresh():
            text_area.delete(1.0, tk.END)
            logs = get_recent_logs(100)
            if logs:
                for line in logs:
                    text_area.insert(tk.END, line + '\n')
            else:
                text_area.insert(tk.END, "暂无日志记录。\n")
            text_area.see(tk.END)

        tk.Button(btn_frame, text="🔄 刷新", command=refresh,
                  bg=self.colors['accent'], fg='white',
                  font=('Microsoft YaHei', 9)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="关闭", command=log_win.destroy,
                  font=('Microsoft YaHei', 9)).pack(side=tk.RIGHT, padx=5)

        refresh()

    # ─── 关闭窗口 ───

    def _on_close(self):
        """关闭窗口确认"""
        if messagebox.askokcancel("退出", "确定要退出 Secure AES 加密系统吗？"):
            self.root.destroy()

    # ─── 启动 ───

    def run(self):
        """启动GUI主循环"""
        self.root.mainloop()


def show_login_dialog() -> bool:
    """显示登录对话框，成功返回 True"""
    import hashlib
    from auth.user_manager import UserManager
    from auth.register import Register
    from auth.login import Login
    from core.password_checker import check_password_strength, generate_strong_password

    login_win = tk.Tk()
    login_win.title("Secure AES 加密系统 - 登录")
    login_win.geometry("420x300")
    login_win.resizable(False, False)
    login_win.configure(bg='#f0f0f0')

    result = {'success': False}

    def do_login():
        username = entry_user.get().strip()
        password = entry_pwd.get()
        if not username or not password:
            msg_var.set("请输入用户名和密码")
            return
        l = Login()
        r = l.login(username, password)
        if r['success']:
            result['success'] = True
            login_win.destroy()
        else:
            msg_var.set("用户名或密码错误")

    def do_register():
        username = entry_user.get().strip()
        password = entry_pwd.get()
        confirm = entry_cfm.get()
        if not username or len(username) < 3:
            msg_var.set("用户名至少3个字符")
            return
        if not password:
            msg_var.set("密码不能为空")
            return
        if password != confirm:
            msg_var.set("两次密码不一致")
            return
        strength = check_password_strength(password)
        if strength['score'] < 50:
            msg_var.set(f"密码强度不足({strength['score']}分)，请使用更强的密码")
            return
        reg = Register()
        r = reg.register(username, password)
        if r['success']:
            msg_var.set("注册成功，请登录")
            entry_cfm.delete(0, tk.END)
            # 自动填入密码
            entry_pwd.delete(0, tk.END)
            entry_pwd.insert(0, password)
        else:
            msg_var.set(r['message'])

    def show_pwd_strength(*args):
        pwd = entry_pwd.get()
        if pwd:
            s = check_password_strength(pwd)
            strength_label.config(text=f"强度: {s['level']} ({s['score']}分)")
        else:
            strength_label.config(text="")

    # 标题
    title_font = Font(family="Microsoft YaHei", size=14, weight="bold")
    tk.Label(login_win, text="Secure AES 加密系统", font=title_font,
             bg='#2c3e50', fg='white').pack(fill=tk.X, pady=(0, 10), ipady=10)

    frame = ttk.Frame(login_win, padding=20)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="用户名:").grid(row=0, column=0, sticky=tk.W, pady=4)
    entry_user = ttk.Entry(frame, width=30)
    entry_user.grid(row=0, column=1, columnspan=2, padx=5)

    ttk.Label(frame, text="密  码:").grid(row=1, column=0, sticky=tk.W, pady=4)
    entry_pwd = ttk.Entry(frame, width=30, show='*')
    entry_pwd.grid(row=1, column=1, columnspan=2, padx=5)
    entry_pwd.bind('<KeyRelease>', show_pwd_strength)

    ttk.Label(frame, text="确认密码:").grid(row=2, column=0, sticky=tk.W, pady=4)
    entry_cfm = ttk.Entry(frame, width=30, show='*')
    entry_cfm.grid(row=2, column=1, columnspan=2, padx=5)

    strength_label = ttk.Label(frame, text="", foreground='#555')
    strength_label.grid(row=3, column=1, columnspan=2, sticky=tk.W, pady=2)

    msg_var = tk.StringVar()
    msg_label = tk.Label(frame, textvariable=msg_var, fg='#e74c3c', bg='#f0f0f0')
    msg_label.grid(row=4, column=0, columnspan=3, pady=5)

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=5, column=0, columnspan=3, pady=10)

    login_btn = tk.Button(btn_frame, text="登录", command=do_login,
                          bg='#3498db', fg='white', width=10,
                          font=('Microsoft YaHei', 10))
    login_btn.pack(side=tk.LEFT, padx=5)

    reg_btn = tk.Button(btn_frame, text="注册", command=do_register,
                        bg='#27ae60', fg='white', width=10,
                        font=('Microsoft YaHei', 10))
    reg_btn.pack(side=tk.LEFT, padx=5)

    # 回车键触发登录
    login_win.bind('<Return>', lambda e: do_login())

    entry_user.focus()
    login_win.mainloop()
    return result['success']


def launch_gui():
    """启动图形界面（先登录，后进入主界面）"""
    if show_login_dialog():
        app = SecureAESGUI()
        app.run()


if __name__ == '__main__':
    launch_gui()
