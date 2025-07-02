# ParseCore
# 🧠 ForenParse

**Author:** Sari  
**Tool Type:** Forensic log parser  
**Dependencies:** None  
**License:** MIT (or your choice)

---

## 🔍 What is ParseCore?

**ParseCore** is a zero-dependency Python tool that intelligently parses raw forensic log files and config files from Unix-like systems.

It supports both **structured parsing** (for files like `passwd`, `shadow`, `group`, `sudoers`) and **flat log parsing** (for `.log`, `.history`, `authorized_keys`, etc.).

---

## ✨ Features

- ✅ Detects and parses both files and folders
- ✅ Auto-detects key Linux artifact formats
- ✅ Converts logs into clean, structured JSON
- ✅ Logs all parsing activity and handles errors per file
- ✅ No external libraries required (pure Python)

---

## 📦 Usage

### 🔧 Run the parser

```bash
python3 parse_logs.py /path/to/file_or/folder
