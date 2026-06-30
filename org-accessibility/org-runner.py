#!/usr/bin/env python3
"""Script to run org source blocks outside of emacs."""
import json
import re
import subprocess
import sys
import tempfile

SRC_BLOCK_RE = re.compile(
    r"#\+BEGIN_SRC\s+(python|sh|shell)[^\n]*\n(.*?)\n#\+END_SRC",
    re.DOTALL | re.IGNORECASE,
)


class Block:
    """Simple class to store data for a block."""
    def __init__(self, heading, depth):
        self.content = {"text": ""}
        self.depth = depth
        self.children = []
        self.heading = heading

class IvyEncoder(json.JSONEncoder):
    """Encoder class for JSON output."""
    def default(self, o):
        """Convert a block to a dictionary readable format for JSON."""
        if isinstance(o,Block):
            return {
                "content": o.content,
                "depth":o.depth,
                "heading":o.heading,
                "children":[self.default(c) for c in o.children]
            }
        else:
            pass


def run_python(code: str):
    """Run python source block."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        f.flush()
        result = subprocess.run(
            ["python3", f.name],
            capture_output=True,
            text=True,
        )
    return result.stdout, result.stderr

def run_shell(code: str):
    """Run python source shell."""
    result = subprocess.run(
        ["sh", "-c", code],
        capture_output=True,
        text=True,
    )
    return result.stdout, result.stderr

def execute_block(lang: str, code: str):
    """Run a code block with the proper interpreter."""
    lang = lang.lower()

    if lang == "python":
        return run_python(code)
    elif lang in ("sh", "shell"):
        return run_shell(code)
    else:
        return "", f"Unsupported language: {lang}\n"

def build_org_tree(f):
    """Convert a file to a Block tree."""
    tree = Block("",0)
    stack = [tree]
    part = "content"
    for line in f:
        stars = 0
        while line[stars] == "*":
            stars+=1
        if stars > 0:
            heading = line[stars+1:][:-1]

            new_node = Block(heading,stars)
            if stars > stack[-1].depth:
                stack[-1].children.append(new_node)
                stack.append(new_node)
                part="text"
            else:
                while stack[-1].depth>=stars:
                    stack.pop()
                stack[-1].children.append(new_node)
                stack.append(new_node)
                part="text"
        else:
            if "#+begin_src" in line.lower():
                src_parts = line.split(" ")
                part = src_parts[1]
                if not stack[-1].content.get(part):
                    stack[-1].content[src_parts[1]] = ""
            elif "#+end_src" in line.lower():
                part = "text"
            else:
                stack[-1].content[part] = stack[-1].content[part] + line
    return tree

def extract_code(block, children=True):
    """Given a block, extract its code by language to a dict."""
    d = {}
    for x in block.content.keys():
        if x != "text":
            d[x] = block.content[x]
    if children:
        for child in block.children:
            new_d = extract_code(child,True)
            for k in new_d.keys():
                if d.get(k):
                    d[k]+="\n"+new_d[k]
                else:
                    d[k]=new_d[k]
    return d



def main(path,headings):
    """Parse the file and run the internal code."""
    with open(path) as f:
        t = build_org_tree(f)


    if len(headings)>0:
        for heading in headings:
            parts = heading.split(".")
            block = t
            for p in parts:
                if lx := [x for x in block.children if x.heading ==p]:
                    block = lx[0]
                else:
                    print("INVALID HEADING")
            block_dict = extract_code(block)

            for lang in block_dict.keys():
                print(f"Running {lang} block:\n{block_dict[lang]}\n")
                out, err = execute_block(lang, block_dict[lang])
                if out:
                    print("--- stdout ---")
                    print(out.rstrip())

                if err:
                    print("--- stderr ---")
                    print(err.rstrip())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: org_runner.py file.org [headings]*")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2:])
