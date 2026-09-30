"""NetBlock — блокировка доменов и IP-адресов (hosts + Windows Firewall)."""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import netblock_core as core

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:  # без трея программа работает как обычное окно
    pystray = None
DATA = os.path.join(APP_DIR, "blocklist.json")


def elevate_if_needed():
    if core.IS_WIN and not core.is_admin():
        import ctypes
        params = " ".join(f'"{a}"' for a in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)


class ListTab(ttk.Frame):
    def __init__(self, master, app, kind):
        super().__init__(master, padding=8)
        self.app, self.kind = app, kind
        self.norm = core.normalize_domain if kind == "domains" else core.normalize_ip
        hint = ("example.com (можно вставить URL)" if kind == "domains"
                else "1.2.3.4, 10.0.0.0/8 или 1.1.1.1-1.1.1.9")
        row = ttk.Frame(self)
        row.pack(fill="x")
        self.entry = ttk.Entry(row)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda e: self.add())
        self.entry.bind("<Control-KeyPress>", self._ctrl_key)  # работает на любой раскладке
        self.entry.bind("<Button-3>", self._context_menu)
        ttk.Button(row, text="Добавить", command=self.add).pack(side="left", padx=(6, 0))
        ttk.Label(self, text=hint, foreground="#666").pack(anchor="w", pady=(2, 6))

        box = ttk.Frame(self)
        box.pack(fill="both", expand=True)
        self.lb = tk.Listbox(box, selectmode="extended", activestyle="none")
        sb = ttk.Scrollbar(box, command=self.lb.yview)
        self.lb.config(yscrollcommand=sb.set)
        self.lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Удалить выбранные", command=self.remove).pack(side="left")
        ttk.Button(btns, text="Импорт из файла…", command=self.import_file).pack(side="left", padx=6)
        self.refresh()

    def _ctrl_key(self, e):
        """Ctrl+V/C/X/A по коду клавиши: на русской раскладке Tk их не распознаёт."""
        if e.keysym.lower() in ("v", "c", "x", "a"):
            return None  # латинская раскладка — стандартная обработка
        w = e.widget
        if e.keycode == 86:
            w.event_generate("<<Paste>>")
        elif e.keycode == 67:
            w.event_generate("<<Copy>>")
        elif e.keycode == 88:
            w.event_generate("<<Cut>>")
        elif e.keycode == 65:
            w.select_range(0, "end")
            w.icursor("end")
        else:
            return None
        return "break"

    def _context_menu(self, e):
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Вставить", command=lambda: e.widget.event_generate("<<Paste>>"))
        m.add_command(label="Копировать", command=lambda: e.widget.event_generate("<<Copy>>"))
        m.add_command(label="Вырезать", command=lambda: e.widget.event_generate("<<Cut>>"))
        m.add_separator()
        m.add_command(label="Выделить всё", command=lambda: e.widget.select_range(0, "end"))
        e.widget.focus_set()
        m.tk_popup(e.x_root, e.y_root)

    @property
    def items(self):
        return getattr(self.app.store, self.kind)

    def refresh(self):
        self.lb.delete(0, "end")
        for x in self.items:
            self.lb.insert("end", x)

    def _add_many(self, raws):
        added, bad = 0, []
        for raw in raws:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            v = self.norm(raw)
            if v is None:
                bad.append(raw)
            elif v not in self.items:
                self.items.append(v)
                added += 1
        self.refresh()
        if added:
            self.app.apply()
        if bad:
            messagebox.showwarning("Некорректные записи", "Пропущено:\n" + "\n".join(bad[:15]))

    def add(self):
        self._add_many(self.entry.get().replace(",", " ").split()
                       if self.kind == "domains" else self.entry.get().split(","))
        self.entry.delete(0, "end")

    def remove(self):
        for i in reversed(self.lb.curselection()):
            del self.items[i]
        self.refresh()
        self.app.apply()

    def import_file(self):
        p = filedialog.askopenfilename(filetypes=[("Текст", "*.txt *.lst *.list"), ("Все", "*.*")])
        if p:
            with open(p, encoding="utf-8", errors="replace") as f:
                self._add_many(f.read().split())


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetBlock — блокировка доменов и IP")
        self.geometry("520x500")
        self.minsize(420, 380)
        self.store = core.Store(DATA)

        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        self.var = tk.BooleanVar(value=self.store.enabled)
        ttk.Checkbutton(top, text="Блокировка включена", variable=self.var,
                        command=self.toggle).pack(side="left")
        self.auto = tk.BooleanVar(value=core.autostart_enabled())
        ttk.Checkbutton(top, text="Запускать с Windows", variable=self.auto,
                        command=self.toggle_autostart).pack(side="right")
        ttk.Button(top, text="Снять всё и выйти", command=self.quit_clean).pack(side="right", padx=8)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self.tabs = [ListTab(nb, self, "domains"), ListTab(nb, self, "ips")]
        nb.add(self.tabs[0], text="Домены")
        nb.add(self.tabs[1], text="IP-адреса")

        self.status = tk.StringVar()
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                  padding=4).pack(fill="x", side="bottom")
        self.apply()
        self.tray = None
        self.fix_autostart_path()
        self.after(5000, self.watchdog)
        self.after(60000, self.fw_watchdog)
        if pystray:
            self.protocol("WM_DELETE_WINDOW", self.hide)
            self.start_tray()
            if "--tray" in sys.argv:  # автозапуск: сразу в трей
                self.withdraw()

    # ---------- проверка целостности ----------
    def watchdog(self):
        """Каждые 5 с проверяет hosts и возвращает блок, если его стёрли (например, VPN)."""
        try:
            doms = self.store.domains if self.store.enabled else []
            if not core.hosts_in_sync(doms):
                core.apply_hosts(doms)
                self.status.set("hosts был изменён сторонней программой — блок восстановлен")
        except Exception as e:  # noqa: BLE001
            self.status.set(f"Проверка hosts: {e}")
        self.after(5000, self.watchdog)

    def fw_watchdog(self):
        """Раз в минуту проверяет правила файрвола (в отдельном потоке, чтобы не вешать окно)."""
        def work():
            try:
                ips = self.store.ips if self.store.enabled else []
                if ips and not core.firewall_in_sync(ips):
                    core.apply_firewall(ips)
                    self.after(0, lambda: self.status.set(
                        "Правила файрвола были удалены — восстановлены"))
                if ips and not core.routes_in_sync(self.store.routes):
                    self.store.routes, _ = core.apply_routes(self.store.routes, ips)
                    self.store.save()
                    self.after(0, lambda: self.status.set("Маршруты блокировки восстановлены"))
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=work, daemon=True).start()
        self.after(60000, self.fw_watchdog)

    # ---------- трей ----------
    def make_icon(self):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        color = (200, 40, 40, 255) if self.store.enabled else (130, 130, 130, 255)
        d.ellipse((4, 4, 60, 60), fill=color)
        d.rectangle((14, 28, 50, 36), fill="white")
        return img

    def start_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem("Открыть", lambda: self.after(0, self.show), default=True),
            pystray.MenuItem("Блокировка включена", lambda: self.after(0, self.tray_toggle),
                             checked=lambda item: self.store.enabled),
            pystray.MenuItem("Выход (блокировки остаются)", lambda: self.after(0, self.quit_app)),
            pystray.MenuItem("Снять всё и выйти", lambda: self.after(0, self.quit_clean)),
        )
        self.tray = pystray.Icon("NetBlock", self.make_icon(), "NetBlock", menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

    def hide(self):
        self.withdraw()

    def show(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def tray_toggle(self):
        self.var.set(not self.store.enabled)
        self.toggle()

    def quit_clean(self):
        """Портативный «деинсталл»: убирает записи из hosts, правила файрвола и маршруты."""
        if not messagebox.askyesno("NetBlock", "Снять все блокировки и выйти?\n"
                                   "Список в blocklist.json сохранится."):
            return
        try:
            core.remove_all(self.store)
            self.store.save()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("NetBlock", f"Не удалось снять блокировки: {e}")
            return
        self.quit_app()

    def fix_autostart_path(self):
        """Если .exe перенесли в другую папку, обновляет путь в задании автозапуска."""
        def work():
            try:
                if getattr(sys, "frozen", False) and core.autostart_enabled():
                    target = core.autostart_target()
                    if target and os.path.normcase(target) != os.path.normcase(sys.executable):
                        core.set_autostart(True, sys.executable, "--tray")
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=work, daemon=True).start()

    def quit_app(self):
        if self.tray:
            self.tray.stop()
        self.destroy()

    def toggle_autostart(self):
        if getattr(sys, "frozen", False):
            exe, args = sys.executable, "--tray"
        else:
            exe = sys.executable.replace("python.exe", "pythonw.exe")
            args = f'"{os.path.abspath(sys.argv[0])}" --tray'
        err = core.set_autostart(self.auto.get(), exe, args)
        if err:
            self.auto.set(core.autostart_enabled())
            messagebox.showerror("Автозапуск", err[:500])
        else:
            self.status.set("Автозапуск включён" if self.auto.get() else "Автозапуск выключен")

    def toggle(self):
        self.store.enabled = self.var.get()
        self.apply()

    def apply(self):
        self.store.save()
        try:
            errs = core.apply_all(self.store)
        except PermissionError as e:
            self.status.set(
                f"Запись в hosts запрещена ({e.strerror or e}). Админ: "
                f"{'да' if core.is_admin() else 'НЕТ'}. Скорее всего, hosts защищает антивирус")
            return
        except Exception as e:  # noqa: BLE001
            self.status.set(f"Ошибка: {e}")
            return
        self.store.save()  # routes обновились внутри apply_all
        state = "активна" if self.store.enabled else "выключена"
        msg = (f"Блокировка {state}: доменов {len(self.store.domains)}, "
               f"IP {len(self.store.ips)}")
        if errs:
            msg += f" | ошибки файрвола: {errs[0][:80]}"
        self.status.set(msg)
        if getattr(self, "tray", None):
            self.tray.icon = self.make_icon()
            self.tray.title = f"NetBlock: {state}"


if __name__ == "__main__":
    elevate_if_needed()
    if not core.single_instance():
        _r = tk.Tk()
        _r.withdraw()
        messagebox.showinfo("NetBlock", "NetBlock уже запущен — ищите значок в трее.")
        sys.exit(0)
    App().mainloop()
