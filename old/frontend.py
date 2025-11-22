import customtkinter as ctk
from typing import Literal, Union, Tuple
def create_root_window():
    root = ctk.CTk()
    root.title("Kryptografia Postkwantowa - Krzysztof Madajczak Jakub Mlocek, Julia Sadecka, Marcel Trzaczawka")
    root.geometry("1000x600")
    root.grid_rowconfigure(2, weight=1)
    return root


def create_sidebar_frame(root, row, column, rowspan, width=300):
    sidebar_frame = ctk.CTkFrame(root, width=width, corner_radius=0)
    sidebar_frame.grid(row=row, column=column, rowspan=rowspan, sticky="nsew", padx=(25, 20))
    sidebar_frame.grid_rowconfigure(4, weight=1)
    return sidebar_frame


def create_label(parent, text, font_size=20, weight: Literal["normal", "bold", None] = "bold", row=0, column=0, padx=40, pady=(20, 10)):
    label = ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=font_size, weight=weight))
    label.grid(row=row, column=column, padx=padx, pady=pady)
    return label


def create_button(parent, text, command=None, row=0, column=0, padx=40, pady: Union[int, Tuple[int, int]]= 10):
    button = ctk.CTkButton(parent, text=text, command=command)
    if isinstance(pady, tuple):
        pady_top, pady_bottom = pady
        button.grid(row=row, column=column, padx=padx, pady=(pady_top, pady_bottom))
    else:
        button.grid(row=row, column=column, padx=padx, pady=pady)
    return button


def create_entry(parent, placeholder_text="", show="", row=0, column=0, padx=40, pady=10):
    entry = ctk.CTkEntry(parent, placeholder_text=placeholder_text, show=show)
    entry.grid(row=row, column=column, padx=padx, pady=pady)
    return entry