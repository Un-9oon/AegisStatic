ENTROPY_THRESHOLD = 6.5
XOR_KEY_RANGE = range(256)

TWO_BYTE_KEYS = [
    0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xFACE, 0xFEED, 0xD00D, 0x1337,
    0x4141, 0x9090, 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xFFFF, 0x0F0F,
    0xF0F0, 0x5A5A, 0xA5A5, 0x1234, 0x4321, 0xABCD, 0xDCBA, 0x6969,
    0x7777, 0x3333, 0x2222, 0x1111, 0x0101, 0x0202, 0x0303, 0x0404,
    0x9999, 0x5555, 0x6666
]

HIGH_VALUE_KEYWORDS = [
    b"http", b"https", b"cmd", b"exe", b"dll", b"powershell",
    b"HKLM", b"HKCU", b"CurrentVersion", b"Software\\Microsoft",
    b"CreateProcess", b"VirtualAlloc", b"WriteProcessMemory",
    b"RegSetValue", b"URLDownloadToFile", b"ShellExecute",
    b"WinExec", b"socket", b"connect", b"recv", b"send",
    b"InternetOpen", b"HttpSendRequest", b"GetProcAddress",
    b"LoadLibrary", b"NtUnmapViewOfSection", b"ZwUnmapViewOfSection",
]

PRINTABLE_THRESHOLD = 0.7
MIN_BLOB_SIZE = 16
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
