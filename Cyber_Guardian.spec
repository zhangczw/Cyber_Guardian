# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Direct pathway to your Python script and the data file
script_dir = '/Users/weiqizhang/DSD_content/Cyber_Guard_File'

# Define data files
datas = [(script_dir + '/Cyber_Guard_File.json', '.')]

# List of hidden imports
hiddenimports = [
    'keyring', 'nacl.encoding', 'nacl.signing', 'bcrypt',
    'tkinter', 'tkinter.filedialog', 'tkinter.messagebox'
]

a = Analysis(
    [script_dir + '/Cyber_Guardian.py'],  # Path directly to your main Python file
    pathex=[script_dir],  # Add the script directory to the analysis path
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Cyber_Guardian',
    debug=True,  # Keep debug mode enabled to catch any issues
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Cyber_Guardian'
)

# Optionally, create a BUNDLE for macOS apps
app = BUNDLE(
    coll,
    name='Cyber_Guardian.app',
    icon=None,  # Specify an icon path if needed
    bundle_identifier=None
)
