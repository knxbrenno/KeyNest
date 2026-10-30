"""
Área de transferência sem dependências externas (Windows, macOS e Linux).

Depois de copiar uma senha, um processo em segundo plano limpa a área de transferência após alguns segundos,
mas só se ela ainda contiver a mesma senha (comparando hashes; a senha não é passada ao processo).
No Windows, a senha também é marcada para não entrar no histórico (Win+V) nem ser sincronizada na nuvem.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import time

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]


def _win_open():
    for _ in range(20):  # Outro programa pode estar usando a área de transferência
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.05)
    return False


def _win_set(fmt, data):
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
    pointer = kernel32.GlobalLock(handle)
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    return bool(user32.SetClipboardData(fmt, handle))


def _win_copy(text):
    if not _win_open():
        return False
    try:
        user32.EmptyClipboard()
        if not text:
            return True
        ok = _win_set(CF_UNICODETEXT, text.encode("utf-16-le") + b"\x00\x00")
        # Formatos reconhecidos pelo Windows 10/11 para não guardar o conteúdo no histórico nem na nuvem.
        zero = (0).to_bytes(4, "little")
        for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
            _win_set(user32.RegisterClipboardFormatW(name), zero)
        return ok
    finally:
        user32.CloseClipboard()


def _win_paste():
    if not _win_open():
        return None
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        pointer = kernel32.GlobalLock(handle)
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _commands():
    if sys.platform == "darwin":
        return (["pbcopy"], ["pbpaste"])
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return (["wl-copy"], ["wl-paste", "--no-newline"])
    if shutil.which("xclip"):
        return (["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"])
    if shutil.which("xsel"):
        return (["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"])
    return (None, None)


def available():
    return sys.platform == "win32" or _commands()[0] is not None


def copy(text):
    if sys.platform == "win32":
        return _win_copy(text)
    copy_cmd, _ = _commands()
    if not copy_cmd:
        return False
    try:
        subprocess.run(copy_cmd, input=text.encode("utf-8"), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def paste():
    if sys.platform == "win32":
        return _win_paste()
    _, paste_cmd = _commands()
    if not paste_cmd:
        return None
    try:
        out = subprocess.run(paste_cmd, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.decode("utf-8", errors="replace")


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clear_later(text, seconds):
    """Agenda a limpeza da área de transferência em um processo separado (sobrevive ao fim do programa)."""
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, "-m", "keynest.clipboard", str(seconds), _digest(text)], **kwargs)


if __name__ == "__main__":
    time.sleep(float(sys.argv[1]))
    current = paste()
    if current is not None and _digest(current) == sys.argv[2]:
        copy("")
