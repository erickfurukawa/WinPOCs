import ctypes
import win32con
MessageBoxA = ctypes.windll.user32.MessageBoxA
hWnd = 0
lpText = ctypes.c_char_p(b"Text")
lpCaption = ctypes.c_char_p(b"Success")
uType = win32con.MB_OK
MessageBoxA(hWnd, lpText, lpCaption, uType)
