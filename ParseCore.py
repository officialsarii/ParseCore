#!/usr/bin/env python3
"""
UACrunch Parser Module
Author: Sari

Parses UAC forensic artifacts from a file or folder into structured JSON.
Handles Linux auth configs and general log files.
"""

import os
import sys
import json
import re

def is_text_file(path, threshold=0.90):
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
        if not chunk:
            return False
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        nontext = [b for b in chunk if b not in text_chars]
        return (len(nontext) / len(chunk)) < (1 - threshold)
    except Exception:
        return False

def parse_structured(path, kind):
    result = []
    with open(path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
    for line in lines:
        parts = line.split(':')
        if kind == "passwd" and len(parts) >= 7:
            result.append({
                "user": parts[0], "uid": parts[2], "gid": parts[3],
                "desc": parts[4], "home": parts[5], "shell": parts[6]
            })
        elif kind == "shadow" and len(parts) >= 2:
            result.append({"user": parts[0], "has_hash": parts[1] not in ["*", "!"]})
        elif kind == "group" and len(parts) >= 3:
            result.append({
                "group": parts[0], "gid": parts[2],
                "members": parts[3].split(',') if len(parts) > 3 else []
            })
        elif kind == "sudoers":
            result.append({"rule": line})
    return result

def parse_generic_log(path):
    with open(path, "r", errors="ignore") as f:
        return [{"line": l.strip()} for l in f if l.strip()]

def save_json(data, outfile):
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)

def parse_file(path, outdir):
    name = os.path.basename(path)
    kind = None
    if "passwd" in name:
        kind = "passwd"
    elif "shadow" in name:
        kind = "shadow"
    elif "group" in name:
        kind = "group"
    elif "sudoers" in name:
        kind = "sudoers"

    try:
        if not is_text_file(path):
            print(f"⚠️ Skipped non-text file: {path}")
            return

        outfile = os.path.join(outdir, name.replace(".", "_") + ".json")
        if kind:
            data = parse_structured(path, kind)
        else:
            data = parse_generic_log(path)

        if data:
            save_json(data, outfile)
            print(f"✅ Parsed: {path} → {outfile}")
        else:
            print(f"⚠️ No data parsed: {path}")

    except Exception as e:
        print(f"❌ Error parsing {path}: {e}")

def parse_path(input_path):
    if not os.path.exists(input_path):
        print("❌ Path does not exist.")
        return

    outdir = os.path.join(os.getcwd(), "parsed_output")
    os.makedirs(outdir, exist_ok=True)

    if os.path.isfile(input_path):
        parse_file(input_path, outdir)
    else:
        for root, _, files in os.walk(input_path):
            for file in files:
                parse_file(os.path.join(root, file), outdir)

    print(f"\n📁 All parsed logs saved to: {outdir}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_logs.py <file_or_folder_path>")
        sys.exit(1)

    parse_path(sys.argv[1])
