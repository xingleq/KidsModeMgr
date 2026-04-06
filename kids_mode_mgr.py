# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import messagebox
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32security
import win32api
import win32con
import ntsecuritycon as con
import time
import os
import ctypes
import winreg
from datetime import datetime, date
import sys
import subprocess
import threading


# =============================================================================
# WTS API
# =============================================================================
WTS_CURRENT_SERVER_HANDLE = 0
WTSActive = 0
MB_OK = 0
MB_ICONWARNING = 0x30
MB_ICONINFORMATION = 0x40

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_uint32),
                ("pWinStationName", ctypes.c_char_p),
                ("State", ctypes.c_uint32)]

wtsapi32 = ctypes.windll.wtsapi32
kernel32 = ctypes.windll.kernel32

def get_active_session_id():
    pSessionInfo = ctypes.POINTER(WTS_SESSION_INFO)()
    pCount = ctypes.c_uint32()
    if wtsapi32.WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                                       ctypes.byref(pSessionInfo), ctypes.byref(pCount)):
        active_session = None
        for i in range(pCount.value):
            sess = pSessionInfo[i]
            if sess.State == WTSActive:
                active_session = sess.SessionId
                break
        wtsapi32.WTSFreeMemory(pSessionInfo)
        return active_session
    return None

def disconnect_session(session_id):
    if session_id is None:
        return
    wtsapi32.WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, False)

def _send_message_blocking(session_id, title, message, style, timeout):
    """在独立线程中阻塞调用 WTSSendMessageW，timeout 秒后弹窗自动关闭。"""
    try:
        response = ctypes.c_uint32(0)
        wtsapi32.WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            ctypes.c_uint32(session_id),
            ctypes.c_wchar_p(title),
            ctypes.c_uint32(len(title) * 2),
            ctypes.c_wchar_p(message),
            ctypes.c_uint32(len(message) * 2),
            ctypes.c_uint32(style),
            ctypes.c_uint32(timeout),
            ctypes.byref(response),
            ctypes.c_bool(True),   # bWait=True，timeout 到期后自动关闭
        )
    except Exception:
        pass

def send_session_message(session_id, title, message, style=MB_ICONWARNING, timeout=3):
    """非阻塞发送弹窗：在后台线程中等待 timeout 秒后自动消失，不影响服务主循环。"""
    if session_id is None:
        return
    t = threading.Thread(
        target=_send_message_blocking,
        args=(session_id, title, message, style, timeout),
        daemon=True,
    )
    t.start()

def get_uptime_seconds():
    """返回系统自启动以来的秒数，不受系统时间修改影响（GetTickCount64 约49天溢出免疫版本）。"""
    return kernel32.GetTickCount64() / 1000.0

def fmt_seconds(secs):
    """将秒数格式化为 mm:ss 或 hh:mm:ss。"""
    secs = max(0, int(secs))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}小时{m:02d}分{s:02d}秒"
    return f"{m}分{s:02d}秒"

# =============================================================================
# 日志
# =============================================================================
# 硬编码路径，避免 SYSTEM 账户与普通用户账户环境变量不一致导致路径错误
LOG_DIR = r"C:\ProgramData\KidsModeMgr"
LOG_FILE = os.path.join(LOG_DIR, "usage.log")

def write_log(message):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass

# =============================================================================
# 注册表 ACL 保护
# =============================================================================
REG_PATH = r"SOFTWARE\KidsModeMgr"

def apply_registry_acl():
    """
    限制 HKLM\\SOFTWARE\\KidsModeMgr 只有 SYSTEM 和 Administrators 可写，
    普通用户只能读。需要管理员权限执行。
    """
    try:
        # 先确保 key 存在
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
        winreg.CloseKey(key)

        sd = win32security.GetNamedSecurityInfo(
            f"MACHINE\\{REG_PATH}",
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()

        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        admins_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        users_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid, None)

        # SYSTEM & Administrators: 完全控制
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  con.KEY_ALL_ACCESS, system_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  con.KEY_ALL_ACCESS, admins_sid)
        # 普通用户：只读
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                  con.KEY_READ, users_sid)

        win32security.SetNamedSecurityInfo(
            f"MACHINE\\{REG_PATH}",
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None
        )
    except Exception as e:
        write_log(f"ACL 设置失败（可忽略）: {e}")

# =============================================================================
# 服务崩溃自动恢复
# =============================================================================
SC_ACTION_RESTART = 1
SC_ACTION_NONE = 0

class SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_int), ("Delay", ctypes.c_uint32)]

class SERVICE_FAILURE_ACTIONS(ctypes.Structure):
    _fields_ = [
        ("dwResetPeriod", ctypes.c_uint32),
        ("lpRebootMsg",   ctypes.c_wchar_p),
        ("lpCommand",     ctypes.c_wchar_p),
        ("cActions",      ctypes.c_uint32),
        ("lpsaActions",   ctypes.POINTER(SC_ACTION)),
    ]

SERVICE_CONFIG_FAILURE_ACTIONS = 2

def configure_service_recovery(svc_name):
    """配置服务失败后自动重启（前3次失败均在5秒后重启）。"""
    try:
        actions = (SC_ACTION * 3)(
            SC_ACTION(SC_ACTION_RESTART, 5000),
            SC_ACTION(SC_ACTION_RESTART, 5000),
            SC_ACTION(SC_ACTION_RESTART, 5000),
        )
        failure_actions = SERVICE_FAILURE_ACTIONS(
            dwResetPeriod=86400,
            lpRebootMsg=None,
            lpCommand=None,
            cActions=3,
            lpsaActions=actions,
        )
        hscm = ctypes.windll.advapi32.OpenSCManagerW(None, None, 0x0001)
        if not hscm:
            return
        hsvc = ctypes.windll.advapi32.OpenServiceW(hscm, svc_name, 0x0001 | 0x0010)
        if hsvc:
            ctypes.windll.advapi32.ChangeServiceConfig2W(
                hsvc, SERVICE_CONFIG_FAILURE_ACTIONS,
                ctypes.byref(failure_actions)
            )
            ctypes.windll.advapi32.CloseServiceHandle(hsvc)
        ctypes.windll.advapi32.CloseServiceHandle(hscm)
    except Exception as e:
        write_log(f"配置服务恢复策略失败: {e}")

# =============================================================================
# 服务类
# =============================================================================
class KidsModeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "KidsModeMgrService"
    _svc_display_name_ = "Kids Mode Manager Service"
    _svc_description_ = "监控电脑使用时间，超过限制后强制锁屏并执行休息策略。"
    _svc_start_type_ = win32service.SERVICE_AUTO_START

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.current_usage_seconds = 0
        self.session_was_active = False

        # 防时间篡改：记录锁屏时的系统 uptime，而非 wall clock
        # uptime_at_lock 存在内存；LastForceLockTime 存 wall clock 作为持久化备份
        self.uptime_at_lock = None

        # 预警状态，避免重复弹窗
        self.warned_3min = False
        self.warned_30sec = False

        # 计时持久化：记录上次写入的分钟数，每分钟写一次
        self.last_persist_minute = -1

        # 服务启动时从注册表恢复当日已用时间
        self._restore_daily_usage()

    # ------------------------------------------------------------------
    # 注册表 helpers
    # ------------------------------------------------------------------
    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except Exception:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            servicemanager.LogInfoMsg(f"Registry Error: {e}")

    # ------------------------------------------------------------------
    # 配置 & 状态
    # ------------------------------------------------------------------
    def load_config(self):
        return {
            "max_usage_seconds":      self._get_reg_value("MaxUsage", 1800),
            "mandatory_rest_seconds": self._get_reg_value("MandatoryRest", 300),
            "enable_mandatory_rest":  bool(self._get_reg_value("EnableRest", 1)),
        }

    def load_lock_state(self):
        """读取上次锁屏的 wall-clock 时间戳（持久化）。"""
        val = self._get_reg_value("LastForceLockTime", "0")
        try:
            return float(val)
        except Exception:
            return 0.0

    def save_lock_state(self, ts):
        self._set_reg_value("LastForceLockTime", str(ts), winreg.REG_SZ)

    # ------------------------------------------------------------------
    # 计时持久化（Task #4）
    # ------------------------------------------------------------------
    def _today_key(self):
        return "DailyUsage_" + date.today().strftime("%Y%m%d")

    def _restore_daily_usage(self):
        """服务启动时恢复当日已用秒数，跨天自动忽略。"""
        val = self._get_reg_value(self._today_key(), 0)
        try:
            self.current_usage_seconds = int(val)
            servicemanager.LogInfoMsg(f"恢复当日已用时间: {self.current_usage_seconds}秒")
        except Exception:
            self.current_usage_seconds = 0

    def _persist_daily_usage(self):
        """每秒写 CurrentUsage 供 GUI 实时读取；每分钟写 DailyUsage 持久化防关机丢失。"""
        usage = int(self.current_usage_seconds)
        # 每秒都更新 CurrentUsage，GUI 3秒轮询时能看到最新值
        self._set_reg_value("CurrentUsage", usage)
        # 每分钟写一次持久化键，减少注册表写入频率
        current_minute = usage // 60
        if current_minute != self.last_persist_minute:
            self.last_persist_minute = current_minute
            self._set_reg_value(self._today_key(), usage)

    # ------------------------------------------------------------------
    # 服务主循环
    # ------------------------------------------------------------------
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        write_log("服务已启动。")
        self.main()

    def main(self):
        while self.is_running:
            if win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                break
            try:
                self.check_logic()
            except Exception as e:
                servicemanager.LogInfoMsg(f"服务运行出错: {e}")

    # ------------------------------------------------------------------
    # 核心逻辑
    # ------------------------------------------------------------------
    def check_logic(self):
        config = self.load_config()
        max_usage        = config["max_usage_seconds"]
        mandatory_rest   = config["mandatory_rest_seconds"]
        enable_rest      = config["enable_mandatory_rest"]

        # 防时间篡改：优先使用 uptime 差值判断休息期（Task #5）
        current_uptime = get_uptime_seconds()
        last_lock_wall = self.load_lock_state()

        active_session = get_active_session_id()

        if active_session is not None:
            # --- 强制休息期检查（最高优先级）---
            if enable_rest and (self.uptime_at_lock is not None or last_lock_wall > 0):
                if self.uptime_at_lock is not None:
                    # 用 uptime 差值，防时间篡改
                    elapsed_rest = current_uptime - self.uptime_at_lock
                else:
                    # 服务重启后 uptime_at_lock 丢失，降级用 wall clock
                    elapsed_rest = time.time() - last_lock_wall

                if elapsed_rest < mandatory_rest:
                    remaining = int(mandatory_rest - elapsed_rest)
                    servicemanager.LogInfoMsg(f"强制休息期，剩余: {remaining}秒")
                    self.current_usage_seconds = 0
                    self.session_was_active = False
                    disconnect_session(active_session)
                    return

            # --- 预警通知 ---
            remaining_usage = max_usage - self.current_usage_seconds
            if remaining_usage <= 180 and not self.warned_3min:
                self.warned_3min = True
                send_session_message(
                    active_session,
                    "  儿童模式提醒  ",
                    f"\n  距离锁屏还有 3 分钟，请准备保存作业。  \n\n"
                    f"  已用时间：{fmt_seconds(self.current_usage_seconds)} / {fmt_seconds(max_usage)}  \n",
                    MB_ICONWARNING,
                    timeout=3,
                )
            if remaining_usage <= 30 and not self.warned_30sec:
                self.warned_30sec = True
                send_session_message(
                    active_session,
                    "  儿童模式提醒  ",
                    f"\n  距离锁屏还有 30 秒！请立即保存！  \n\n"
                    f"  已用时间：{fmt_seconds(self.current_usage_seconds)} / {fmt_seconds(max_usage)}  \n",
                    MB_ICONWARNING,
                    timeout=3,
                )

            # --- 正常计时 ---
            self.session_was_active = True
            self.current_usage_seconds += 1
            self._persist_daily_usage()

            if self.current_usage_seconds >= max_usage:
                servicemanager.LogInfoMsg(f"达到最大使用时间 {max_usage}秒，执行锁屏。")
                write_log(f"锁屏触发，当日已用: {fmt_seconds(self.current_usage_seconds)}。")
                lock_ts = time.time()
                self.save_lock_state(lock_ts)
                self.uptime_at_lock = current_uptime  # 用 uptime 标记锁屏时刻
                disconnect_session(active_session)
                self.current_usage_seconds = 0
                self.session_was_active = False
                self.warned_3min = False
                self.warned_30sec = False
                self._set_reg_value("CurrentUsage", 0)
        else:
            self.session_was_active = False

# =============================================================================
# GUI
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

class KidsModeManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("儿童模式管理工具")
        self.geometry("480x760")
        self.resizable(False, False)

        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, 'app_icon.ico')
            else:
                icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_icon.ico')
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception:
            pass

        self.create_widgets()
        self.load_config()
        self.refresh_service_status()
        self._update_status_panel()

    # ------------------------------------------------------------------
    # 注册表 helpers（GUI 层）
    # ------------------------------------------------------------------
    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except Exception:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            raise e

    def _is_service_running(self):
        try:
            return win32serviceutil.QueryServiceStatus(KidsModeService._svc_name_)[1] == win32service.SERVICE_RUNNING
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 界面构建
    # ------------------------------------------------------------------
    def create_widgets(self):
        # ---- 参数设置 ----
        config_frame = tk.LabelFrame(self, text="参数设置", padx=15, pady=10)
        config_frame.pack(padx=15, pady=12, fill="x")

        # 最大使用时间（分钟）
        tk.Label(config_frame, text="最大使用时间:").grid(row=0, column=0, sticky="w", pady=6)
        frm_u = tk.Frame(config_frame)
        frm_u.grid(row=0, column=1, sticky="w", pady=6)
        self.entry_max_usage = tk.Entry(frm_u, width=7)
        self.entry_max_usage.pack(side="left")
        tk.Label(frm_u, text="分钟").pack(side="left", padx=4)
        self.lbl_max_usage_hint = tk.Label(frm_u, text="= 1800秒", fg="gray", font=("Microsoft YaHei UI", 8))
        self.lbl_max_usage_hint.pack(side="left")
        self.entry_max_usage.bind("<KeyRelease>", lambda e: self._update_hints())

        # 强制休息时间（分钟）
        tk.Label(config_frame, text="强制休息时间:").grid(row=1, column=0, sticky="w", pady=6)
        frm_r = tk.Frame(config_frame)
        frm_r.grid(row=1, column=1, sticky="w", pady=6)
        self.entry_mandatory_rest = tk.Entry(frm_r, width=7)
        self.entry_mandatory_rest.pack(side="left")
        tk.Label(frm_r, text="分钟").pack(side="left", padx=4)
        self.lbl_rest_hint = tk.Label(frm_r, text="= 300秒", fg="gray", font=("Microsoft YaHei UI", 8))
        self.lbl_rest_hint.pack(side="left")
        self.entry_mandatory_rest.bind("<KeyRelease>", lambda e: self._update_hints())

        self.var_enable_rest = tk.BooleanVar()
        tk.Checkbutton(config_frame, text="开启强制休息", variable=self.var_enable_rest).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=6)

        tk.Button(config_frame, text="保存配置", command=self.save_config,
                  width=20, bg="#f0f0f0").grid(row=3, column=0, columnspan=2, pady=10)

        # ---- 实时状态面板（Task #10）----
        stat_frame = tk.LabelFrame(self, text="实时状态", padx=15, pady=10)
        stat_frame.pack(padx=15, pady=4, fill="x")

        self.lbl_today_used   = tk.Label(stat_frame, text="今日已用：--", anchor="w",
                                          font=("Microsoft YaHei UI", 10))
        self.lbl_today_used.pack(fill="x", pady=2)
        self.lbl_remaining    = tk.Label(stat_frame, text="距锁屏剩余：--", anchor="w",
                                          font=("Microsoft YaHei UI", 10))
        self.lbl_remaining.pack(fill="x", pady=2)
        self.lbl_rest_remain  = tk.Label(stat_frame, text="", anchor="w",
                                          font=("Microsoft YaHei UI", 10), fg="red")
        self.lbl_rest_remain.pack(fill="x", pady=2)

        # ---- 服务控制 ----
        control_frame = tk.LabelFrame(self, text="服务控制", padx=15, pady=10)
        control_frame.pack(padx=15, pady=4, fill="x")

        self.btn_install   = tk.Button(control_frame, text="安装服务",   command=self.install_service,   width=18)
        self.btn_install.grid(row=0, column=0, padx=8, pady=6)
        self.btn_restart   = tk.Button(control_frame, text="重启服务",   command=self.restart_service,   width=18)
        self.btn_restart.grid(row=0, column=1, padx=8, pady=6)
        self.btn_stop      = tk.Button(control_frame, text="停止服务",   command=self.stop_service,      width=18)
        self.btn_stop.grid(row=1, column=0, padx=8, pady=6)
        self.btn_uninstall = tk.Button(control_frame, text="卸载服务",   command=self.uninstall_service, width=18)
        self.btn_uninstall.grid(row=1, column=1, padx=8, pady=6)

        status_frame = tk.Frame(control_frame, pady=6)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.lbl_status = tk.Label(status_frame, text="服务状态: 未知", fg="gray",
                                    font=("Microsoft YaHei UI", 11, "bold"))
        self.lbl_status.pack()

        # ---- 使用记录 ----
        log_frame = tk.LabelFrame(self, text="使用记录", padx=10, pady=8)
        log_frame.pack(padx=15, pady=4, fill="both", expand=True)

        btn_bar = tk.Frame(log_frame)
        btn_bar.pack(fill="x", pady=(0, 4))
        tk.Button(btn_bar, text="刷新记录", command=self._refresh_log, width=12).pack(side="left")
        tk.Label(btn_bar, text=LOG_FILE, fg="gray",
                 font=("Microsoft YaHei UI", 7)).pack(side="left", padx=8)

        self.log_text = tk.Text(log_frame, height=8, state=tk.DISABLED,
                                font=("Consolas", 9), bg="#f8f8f8", relief="flat",
                                wrap="none")
        sb = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        self._refresh_log()

    # ------------------------------------------------------------------
    # 实时换算提示（Task #11）
    # ------------------------------------------------------------------
    def _update_hints(self):
        for entry, lbl in [(self.entry_max_usage, self.lbl_max_usage_hint),
                           (self.entry_mandatory_rest, self.lbl_rest_hint)]:
            try:
                mins = int(entry.get())
                lbl.config(text=f"= {mins * 60}秒", fg="gray")
            except ValueError:
                lbl.config(text="请输入整数", fg="red")

    # ------------------------------------------------------------------
    # 实时状态轮询（Task #10）
    # ------------------------------------------------------------------
    def _update_status_panel(self):
        try:
            max_usage      = self._get_reg_value("MaxUsage", 1800)
            mandatory_rest = self._get_reg_value("MandatoryRest", 300)
            current_usage  = self._get_reg_value("CurrentUsage", 0)
            last_lock_str  = self._get_reg_value("LastForceLockTime", "0")
            try:
                last_lock = float(last_lock_str)
            except Exception:
                last_lock = 0.0

            self.lbl_today_used.config(
                text=f"今日已用：{fmt_seconds(current_usage)} / {fmt_seconds(max_usage)}"
            )

            now = time.time()
            if last_lock > 0:
                elapsed_rest = now - last_lock
                enable_rest = bool(self._get_reg_value("EnableRest", 1))
                if enable_rest and elapsed_rest < mandatory_rest:
                    rest_remain = int(mandatory_rest - elapsed_rest)
                    self.lbl_rest_remain.config(
                        text=f"休息期剩余：{fmt_seconds(rest_remain)}"
                    )
                    self.lbl_remaining.config(text="距锁屏剩余：（休息期中）")
                else:
                    self.lbl_rest_remain.config(text="")
                    remaining = max(0, max_usage - current_usage)
                    self.lbl_remaining.config(text=f"距锁屏剩余：{fmt_seconds(remaining)}")
            else:
                self.lbl_rest_remain.config(text="")
                remaining = max(0, max_usage - current_usage)
                self.lbl_remaining.config(text=f"距锁屏剩余：{fmt_seconds(remaining)}")
        except Exception:
            pass
        # 每 3 秒刷新
        self.after(3000, self._update_status_panel)

    # ------------------------------------------------------------------
    # 配置读写（Task #11 单位转换）
    # ------------------------------------------------------------------
    def load_config(self):
        try:
            max_usage_sec   = self._get_reg_value("MaxUsage", 1800)
            rest_sec        = self._get_reg_value("MandatoryRest", 300)
            enable_rest     = bool(self._get_reg_value("EnableRest", 1))
            self.entry_max_usage.delete(0, tk.END)
            self.entry_max_usage.insert(0, str(max_usage_sec // 60))
            self.entry_mandatory_rest.delete(0, tk.END)
            self.entry_mandatory_rest.insert(0, str(rest_sec // 60))
            self.var_enable_rest.set(enable_rest)
            self._update_hints()
        except Exception as e:
            messagebox.showerror("错误", f"读取配置失败: {e}")

    def save_config(self):
        try:
            max_usage_min = int(self.entry_max_usage.get())
            rest_min      = int(self.entry_mandatory_rest.get())
            if max_usage_min <= 0 or rest_min <= 0:
                raise ValueError("时间必须大于 0")
            enable_rest = 1 if self.var_enable_rest.get() else 0
            self._set_reg_value("MaxUsage",       max_usage_min * 60)
            self._set_reg_value("MandatoryRest",  rest_min * 60)
            self._set_reg_value("EnableRest",     enable_rest)
        except ValueError as e:
            messagebox.showerror("错误", f"请输入有效的正整数分钟数：{e}")
            return
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {e}")
            return

        # Task #12: 服务运行中时询问是否立即重启生效
        if self._is_service_running():
            if messagebox.askyesno("重启服务", "配置已保存。\n是否立即重启服务以使新配置生效？"):
                self.restart_service(silent=True)
        else:
            messagebox.showinfo("成功", "配置已保存。")

    # ------------------------------------------------------------------
    # 服务控制
    # ------------------------------------------------------------------
    def _get_exe_path(self):
        """获取当前可执行文件路径（兼容 PyInstaller 打包和直接运行）。"""
        if getattr(sys, 'frozen', False):
            return sys.executable          # 打包后的 exe 本身
        else:
            return os.path.abspath(__file__)  # 开发时用脚本路径

    def install_service(self):
        """直接调用 win32serviceutil 注册服务，再通过 SCM API 启动，不走子进程。"""
        exe = self._get_exe_path()
        svc_name = KidsModeService._svc_name_
        try:
            # 注册服务（等价于 HandleCommandLine install）
            win32serviceutil.InstallService(
                None,                             # 使用类默认的 pythonClassString
                svc_name,
                KidsModeService._svc_display_name_,
                startType=win32service.SERVICE_AUTO_START,
                exeName=exe,
                description=KidsModeService._svc_description_,
            )
        except Exception as e:
            # 如果已安装则忽略
            if "already exists" not in str(e).lower() and "1073" not in str(e):
                messagebox.showerror("安装失败", f"注册服务失败:\n{e}")
                return

        # 启动服务
        try:
            win32serviceutil.StartService(svc_name)
        except Exception as e:
            if "already running" not in str(e).lower() and "1056" not in str(e):
                messagebox.showwarning("提示", f"服务已注册，但启动失败（可手动重启）:\n{e}")

        # 配置崩溃恢复策略和注册表 ACL
        configure_service_recovery(svc_name)
        apply_registry_acl()
        write_log("服务已安装，崩溃恢复策略和注册表 ACL 已配置。")
        messagebox.showinfo("成功", "服务安装成功（已设为开机自动启动）。")
        self.refresh_service_status()

    def restart_service(self, silent=False):
        try:
            win32serviceutil.RestartService(KidsModeService._svc_name_)
            if not silent:
                messagebox.showinfo("成功", "服务已重启")
        except Exception as e:
            if not silent:
                messagebox.showerror("失败", f"重启服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def stop_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已停止")
        except Exception as e:
            messagebox.showerror("失败", f"停止服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def uninstall_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
        except Exception:
            pass
        try:
            win32serviceutil.RemoveService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已卸载")
        except Exception as e:
            messagebox.showerror("失败", f"卸载服务失败:\n{e}")
        finally:
            self.refresh_service_status()

    def refresh_service_status(self):
        status_text, status_color, is_installed = "未知", "gray", False
        try:
            status = win32serviceutil.QueryServiceStatus(KidsModeService._svc_name_)[1]
            if status == win32service.SERVICE_RUNNING:
                status_text, status_color = "运行中", "green"
            elif status == win32service.SERVICE_STOPPED:
                status_text, status_color = "已停止", "red"
            else:
                status_text, status_color = "其他状态", "orange"
            is_installed = True
        except Exception:
            status_text, status_color, is_installed = "未安装", "black", False

        self.lbl_status.config(text=f"服务状态: {status_text}", fg=status_color)
        if is_installed:
            self.btn_install.config(state=tk.DISABLED)
            self.btn_restart.config(state=tk.NORMAL)
            self.btn_uninstall.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.NORMAL if status == win32service.SERVICE_RUNNING else tk.DISABLED)
        else:
            self.btn_install.config(state=tk.NORMAL)
            self.btn_restart.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_uninstall.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # 使用记录
    # ------------------------------------------------------------------
    def _refresh_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        if not os.path.exists(LOG_FILE):
            self.log_text.insert(tk.END, "暂无使用记录。")
        else:
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                # 显示最近 50 条
                for line in lines[-50:]:
                    self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
            except Exception as e:
                self.log_text.insert(tk.END, f"读取日志失败: {e}")
        self.log_text.config(state=tk.DISABLED)

# =============================================================================
# 主入口
# =============================================================================
if __name__ == '__main__':
    if len(sys.argv) > 1:
        win32serviceutil.HandleCommandLine(KidsModeService)
    else:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(KidsModeService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            if "1063" in str(e):
                if not is_admin():
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                else:
                    app = KidsModeManager()
                    app.mainloop()
            else:
                pass
