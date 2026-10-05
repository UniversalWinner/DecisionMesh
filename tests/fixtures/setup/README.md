# Synthetic setup evidence

synthetic-preview.txt is the exact fixed content shown before the explicit test action. It contains no host/source details, credential, actual request or remote response action. Tests use invented numeric bot/recipient identities, generated short-lived codes, fake Telegram I/O and temporary owner-only setup/store files.

Keyring-stack tests replace every Windows credential read/write/delete call with a dictionary before exercising the real installed backend. Windows integration tests replace the OS adapter; they do not register tasks, create actual Start Menu links, alter host hooks, or qualify native trust. The local synthetic spool/import smoke verifies only the explicit local callback path.
