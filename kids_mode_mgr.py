# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import messagebox
import win32serviceutil
import win32service
import win32event
import servicemanager
import time
import os
import ctypes
import winreg
from datetime import datetime
import sys
import subprocess

# =============================================================================
# WTS API Constants
# =============================================================================
WTS_CURRENT_SERVER_HANDLE = 0
WTSActive = 0

class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_uint32),
                ("pWinStationName", ctypes.c_char_p),
                ("State", ctypes.c_uint32)]

wtsapi32 = ctypes.windll.wtsapi32
kernel32 = ctypes.windll.kernel32

def get_active_session_id():
    pSessionInfo = ctypes.POINTER(WTS_SESSION_INFO)()
    pCount = ctypes.c_uint32()
    if wtsapi32.WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, ctypes.byref(pSessionInfo), ctypes.byref(pCount)):
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
    if session_id is None: return
    wtsapi32.WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, session_id, False)

# =============================================================================
# Service Class
# =============================================================================
class KidsModeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "KidsModeMgrService"
    _svc_display_name_ = "Kids Mode Manager Service"
    _svc_description_ = "监控电脑使用时间，超过限制后强制锁屏并执行休息策略。"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        
        try:
            self.base_path = os.path.dirname(os.path.abspath(__file__))
        except:
            self.base_path = "C:\\KidsModeMgr"
            
        self.current_usage_seconds = 0
        self.last_active_session = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KidsModeMgr", 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KidsModeMgr")
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            servicemanager.LogInfoMsg(f"Registry Error: {e}")

    def load_config(self):
        return {
            "max_usage_seconds": self._get_reg_value("MaxUsage", 1800),
            "mandatory_rest_seconds": self._get_reg_value("MandatoryRest", 300),
            "enable_mandatory_rest": bool(self._get_reg_value("EnableRest", 1))
        }

    def load_state(self):
        val = self._get_reg_value("LastForceLockTime", "0")
        try:
            return {"last_force_lock_time": float(val)}
        except:
            return {"last_force_lock_time": 0}

    def save_state(self, state):
        val = str(state.get("last_force_lock_time", 0))
        self._set_reg_value("LastForceLockTime", val, winreg.REG_SZ)

    def main(self):
        while self.is_running:
            if win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                break
            try:
                self.check_logic()
            except Exception as e:
                servicemanager.LogInfoMsg(f"服务运行出错: {e}")

    def check_logic(self):
        config = self.load_config()
        max_usage = config.get("max_usage_seconds", 1800)
        mandatory_rest = config.get("mandatory_rest_seconds", 300)
        state = self.load_state()
        last_force_lock_time = state.get("last_force_lock_time", 0)
        enable_mandatory_rest = config.get("enable_mandatory_rest", True)
        current_time = time.time()
        active_session = get_active_session_id()
        
        if active_session is not None:
            if self.last_active_session != active_session:
                self.current_usage_seconds = 0
                self.last_active_session = active_session

            if enable_mandatory_rest:
                time_since_last_lock = current_time - last_force_lock_time
                if time_since_last_lock < mandatory_rest:
                    remaining_time = int(mandatory_rest - time_since_last_lock)
                    servicemanager.LogInfoMsg(f"处于强制休息期，禁止登录。剩余休息时间: {remaining_time}秒")
                    disconnect_session(active_session)
                    return

            self.current_usage_seconds += 1
            if self.current_usage_seconds >= max_usage:
                servicemanager.LogInfoMsg(f"已达到最大使用时间 {max_usage}秒，正在执行锁屏...")
                state["last_force_lock_time"] = current_time
                self.save_state(state)
                disconnect_session(active_session)
                self.current_usage_seconds = 0
        else:
            self.current_usage_seconds = 0
            self.last_active_session = None

# =============================================================================
# GUI Manager Class
# =============================================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class KidsModeManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("儿童模式管理工具 (Kids Mode Manager)")
        self.geometry("420x450")
        self.resizable(False, False)
        
        # 设置窗口图标
        try:
            # 如果是打包后的环境
            if getattr(sys, 'frozen', False):
                # PyInstaller 会将资源解压到 sys._MEIPASS
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

    def _get_reg_value(self, name, default):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KidsModeMgr", 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return value
        except:
            return default

    def _set_reg_value(self, name, value, val_type=winreg.REG_DWORD):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\KidsModeMgr")
            winreg.SetValueEx(key, name, 0, val_type, value)
            winreg.CloseKey(key)
        except Exception as e:
            raise e

    def create_widgets(self):
        config_frame = tk.LabelFrame(self, text="参数设置", padx=15, pady=15)
        config_frame.pack(padx=15, pady=15, fill="x")
        
        tk.Label(config_frame, text="最大使用时间(秒):").grid(row=0, column=0, sticky="w", pady=8)
        self.entry_max_usage = tk.Entry(config_frame, width=25)
        self.entry_max_usage.grid(row=0, column=1, pady=8, padx=5)
        
        tk.Label(config_frame, text="强制休息时间(秒):").grid(row=1, column=0, sticky="w", pady=8)
        self.entry_mandatory_rest = tk.Entry(config_frame, width=25)
        self.entry_mandatory_rest.grid(row=1, column=1, pady=8, padx=5)
        
        self.var_enable_rest = tk.BooleanVar()
        tk.Checkbutton(config_frame, text="开启强制休息", variable=self.var_enable_rest).grid(row=2, column=0, columnspan=2, sticky="w", pady=8)
        
        tk.Button(config_frame, text="保存配置", command=self.save_config, width=20, bg="#f0f0f0").grid(row=3, column=0, columnspan=2, pady=10)
        
        control_frame = tk.LabelFrame(self, text="服务控制", padx=15, pady=15)
        control_frame.pack(padx=15, pady=5, fill="x")
        
        self.btn_install = tk.Button(control_frame, text="安装服务", command=self.install_service, width=18)
        self.btn_install.grid(row=0, column=0, padx=8, pady=8)
        self.btn_restart = tk.Button(control_frame, text="重启服务", command=self.restart_service, width=18)
        self.btn_restart.grid(row=0, column=1, padx=8, pady=8)
        self.btn_stop = tk.Button(control_frame, text="停止服务", command=self.stop_service, width=18)
        self.btn_stop.grid(row=1, column=0, padx=8, pady=8)
        self.btn_uninstall = tk.Button(control_frame, text="卸载服务", command=self.uninstall_service, width=18)
        self.btn_uninstall.grid(row=1, column=1, padx=8, pady=8)

        status_frame = tk.Frame(control_frame, pady=10)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.lbl_status = tk.Label(status_frame, text="服务状态: 未知", fg="gray", font=("Microsoft YaHei UI", 11, "bold"))
        self.lbl_status.pack()

    def load_config(self):
        try:
            max_usage = self._get_reg_value("MaxUsage", 1800)
            mandatory_rest = self._get_reg_value("MandatoryRest", 300)
            enable_rest = bool(self._get_reg_value("EnableRest", 1))
            self.entry_max_usage.delete(0, tk.END)
            self.entry_max_usage.insert(0, str(max_usage))
            self.entry_mandatory_rest.delete(0, tk.END)
            self.entry_mandatory_rest.insert(0, str(mandatory_rest))
            self.var_enable_rest.set(enable_rest)
        except Exception as e:
            messagebox.showerror("错误", f"读取配置失败: {e}")

    def save_config(self):
        try:
            max_usage = int(self.entry_max_usage.get())
            mandatory_rest = int(self.entry_mandatory_rest.get())
            enable_rest = 1 if self.var_enable_rest.get() else 0
            self._set_reg_value("MaxUsage", max_usage)
            self._set_reg_value("MandatoryRest", mandatory_rest)
            self._set_reg_value("EnableRest", enable_rest)
            messagebox.showinfo("成功", "配置已保存到注册表，请重启服务生效。")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字。")
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {e}")

    def run_command(self, args, success_msg):
        # 使用当前 exe 自身作为服务程序
        exe_path = sys.executable
        cmd = [exe_path] + args
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
            if result.returncode == 0:
                messagebox.showinfo("成功", success_msg)
            else:
                if "Error" in result.stdout or "Error" in result.stderr:
                    messagebox.showerror("失败", f"操作失败:\n{result.stdout}\n{result.stderr}")
                else:
                    messagebox.showinfo("提示", f"{success_msg}\n{result.stdout}")
        except Exception as e:
            messagebox.showerror("错误", f"执行命令出错: {e}")
        finally:
            self.refresh_service_status()

    def install_service(self):
        self.run_command(["install"], "服务安装成功")
        try: win32serviceutil.StartService(KidsModeService._svc_name_)
        except: pass
        self.refresh_service_status()

    def restart_service(self):
        self.run_command(["restart"], "服务已重启")

    def stop_service(self):
        try:
            win32serviceutil.StopService(KidsModeService._svc_name_)
            messagebox.showinfo("成功", "服务已停止")
        except:
            self.run_command(["stop"], "服务已停止")
        finally:
            self.refresh_service_status()

    def uninstall_service(self):
        try: win32serviceutil.StopService(KidsModeService._svc_name_)
        except: pass
        self.run_command(["remove"], "服务已卸载")

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
        except:
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

# =============================================================================
# Main Entry Point
# =============================================================================
if __name__ == '__main__':
    if len(sys.argv) > 1:
        # 有参数，交给 pywin32 处理 (install, remove, start, debug, etc.)
        win32serviceutil.HandleCommandLine(KidsModeService)
    else:
        # 无参数，可能是 SCM 启动（服务模式），也可能是用户双击（GUI 模式）
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(KidsModeService)
            # 尝试连接服务控制器。如果是 SCM 启动，这里会成功并阻塞直到服务停止。
            # 如果是用户双击，这里会抛出错误 1063 (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            # 捕获异常，判断是否为 1063 错误
            if "1063" in str(e):
                # 说明不是由 SCM 启动的，进入 GUI 模式
                if not is_admin():
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                else:
                    app = KidsModeManager()
                    app.mainloop()
            else:
                # 其他严重错误，记录到事件日志
                pass
