import ctypes
from ctypes import POINTER, Structure, Union, byref, c_ubyte, c_void_p, c_wchar_p, windll, wintypes

_LPCWSTR = c_wchar_p
_DWORD = wintypes.DWORD
_HANDLE = wintypes.HANDLE

class _GUID(Structure):
    _fields_ = [("Data1", _DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", c_ubyte * 8)]

def _guid(d1: int, d2: int, d3: int, d4: list[int]) -> _GUID:
    g = _GUID()
    g.Data1, g.Data2, g.Data3 = d1, d2, d3
    for i, b in enumerate(d4):
        g.Data4[i] = b
    return g

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
ERROR_SUCCESS = 0

_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _guid(
    0xAAC9, 0xCD44, 0x11D0, [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE])

class _WINTRUST_FILE_INFO(Structure):
    _fields_ = [("cbStruct", _DWORD), ("pcwszFilePath", _LPCWSTR),
                ("hFile", _HANDLE), ("pgKnownSubject", c_void_p)]

class _WINTRUST_UNION(Union):
    _fields_ = [("pFile", POINTER(_WINTRUST_FILE_INFO)), ("pCatalog", c_void_p),
                ("pBlob", c_void_p), ("pSgnr", c_void_p), ("pCert", c_void_p)]

class _WINTRUST_DATA(Structure):
    _anonymous_ = ("Union",)
    _fields_ = [
        ("cbStruct", _DWORD),
        ("pPolicyCallbackData", c_void_p),
        ("pSIPStateData", c_void_p),
        ("dwUIChoice", _DWORD),
        ("fdwRevocationChecks", _DWORD),
        ("dwUnionChoice", _DWORD),
        ("Union", _WINTRUST_UNION),
        ("dwStateAction", _DWORD),
        ("hWVTStateData", _HANDLE),
        ("pwszURLReference", _LPCWSTR),
        ("dwProvFlags", _DWORD),
        ("dwUIContext", _DWORD),
        ("pSignatureSettings", c_void_p),
    ]

_wintrust = None
try:
    _wintrust = windll.wintrust
except OSError:
    _wintrust = None

def has_embedded_signature(path: str) -> bool:
    """True when the file carries a valid embedded Authenticode signature."""
    if _wintrust is None or not path:
        return False
    try:
        info = _WINTRUST_FILE_INFO()
        info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        info.pcwszFilePath = path
        data = _WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.pFile = byref(info)
        rc = _wintrust.WinVerifyTrust(0, byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), byref(data))
        data.dwStateAction = WTD_STATEACTION_CLOSE
        _wintrust.WinVerifyTrust(0, byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2), byref(data))
        return rc == ERROR_SUCCESS
    except Exception:
        return False
