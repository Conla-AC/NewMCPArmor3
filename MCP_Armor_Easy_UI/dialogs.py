# -*- coding: utf-8 -*-
"""Small scrollable dialogs with a footer outside the scrolling viewport."""
import tkinter as tk
from tkinter import ttk


class ScrollDialog(tk.Toplevel):
    def __init__(self, owner, title, width=680, height=580, on_cancel=None):
        super().__init__(owner)
        self.title(title)
        self.transient(owner)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.geometry('%dx%d' % (min(width, self.winfo_screenwidth() - 60),
                                  min(height, self.winfo_screenheight() - 100)))
        self.minsize(360, 220)
        self.viewport = ttk.Frame(self)
        self.viewport.grid(row=0, column=0, sticky='nsew')
        self.viewport.rowconfigure(0, weight=1)
        self.viewport.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(self.viewport, highlightthickness=0, background='#efefef')
        self.canvas.grid(row=0, column=0, sticky='nsew')
        self.scrollbar = ttk.Scrollbar(self.viewport, orient='vertical', command=self.canvas.yview)
        self.scrollbar.grid(row=0, column=1, sticky='ns')
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.body = ttk.Frame(self.canvas, padding=12)
        self.window_id = self.canvas.create_window(0, 0, window=self.body, anchor='nw')
        self.body.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(self.window_id, width=e.width))
        # Toplevel bindtags receive events from their own descendants only.
        self.bind('<MouseWheel>', self._wheel, add='+')
        self.bind('<Button-4>', lambda e: self.canvas.yview_scroll(-1, 'units'), add='+')
        self.bind('<Button-5>', lambda e: self.canvas.yview_scroll(1, 'units'), add='+')
        ttk.Separator(self).grid(row=1, column=0, sticky='ew')
        self.footer = ttk.Frame(self, padding=(10, 8))
        self.footer.grid(row=2, column=0, sticky='ew')
        self.vars = {}
        self.controls = {}
        self.on_cancel = on_cancel
        self.protocol('WM_DELETE_WINDOW', self.cancel)
        self.bind('<Escape>', lambda e: self.cancel())
        self.grab_set()

    def _wheel(self, event):
        if event.widget.winfo_class() not in ('TCombobox', 'Text'):
            self.canvas.yview_scroll(-int(event.delta / 120) or (-1 if event.delta > 0 else 1), 'units')
            return 'break'

    def cancel(self):
        callback = self.on_cancel
        self.close()
        if callback:
            callback()

    def close(self):
        self.grab_release()
        owner = self.master
        self.destroy()
        if isinstance(owner, tk.Toplevel) and owner.winfo_exists():
            owner.grab_set()

    def button(self, text, command, side='right'):
        button = ttk.Button(self.footer, text=text, command=command)
        button.pack(side=side, padx=4)
        return button

    def field(self, parent, key, text, value, choices=None, bounds=None):
        row = ttk.Frame(parent)
        row.pack(fill='x', pady=4)
        ttk.Label(row, text=text, width=26).pack(side='left')
        variable = tk.StringVar(self, value=str(value))
        if choices is not None:
            widget = ttk.Combobox(row, textvariable=variable, values=choices, state='readonly')
        elif bounds is not None:
            widget = ttk.Spinbox(row, textvariable=variable, from_=bounds[0], to=bounds[1], width=12)
        else:
            widget = ttk.Entry(row, textvariable=variable)
        widget.pack(side='left', fill='x', expand=True)
        self.vars[key], self.controls[key] = variable, widget
        return widget

    def checks(self, parent, fields, values, label):
        grid = ttk.Frame(parent)
        grid.pack(fill='x', pady=6)
        for col in (0, 1):
            grid.columnconfigure(col, weight=1)
        for i, (key, en, cn) in enumerate(fields):
            var = tk.BooleanVar(self, value=bool(values.get(key)))
            widget = ttk.Checkbutton(grid, text=label(en, cn), variable=var)
            widget.grid(row=i // 2, column=i % 2, sticky='w', padx=3, pady=4)
            self.vars[key], self.controls[key] = var, widget
        return grid\n