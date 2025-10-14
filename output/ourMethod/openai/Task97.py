import os
import re
import sys
from pathlib import Path
from typing import List
import xml.etree.ElementTree as ET

MAX_FILE_SIZE_BYTES = 5_000_000
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def execute_xpath(xml_path_param: str, id_param: str) -> List[str]:
    base_dir = Path(".").resolve()
    return execute_xpath_with_base_dir(base_dir, xml_path_param, id_param)


def execute_xpath_with_base_dir(base_dir: Path, xml_path_param: str, id_param: str) -> List[str]:
    if not isinstance(id_param, str) or not ID_RE.fullmatch(id_param or ""):
        raise ValueError("Invalid id parameter. Allowed: 1-128 of [A-Za-z0-9._:-]")
    if not isinstance(xml_path_param, str) or len(xml_path_param) == 0 or len(xml_path_param) > 4096:
        raise ValueError("Invalid xml path parameter.")

    # Resolve and validate path within base_dir
    base_real = base_dir.resolve()
    requested = (base_real / xml_path_param).resolve(strict=True)
    if os.path.commonpath([str(requested), str(base_real)]) != str(base_real):
        raise PermissionError("Resolved path escapes base directory.")
    if requested.is_symlink():
        raise PermissionError("Refusing to process symlinked file.")
    if not requested.is_file():
        raise FileNotFoundError("Provided path is not a regular file.")

    size = requested.stat().st_size
    if size <= 0 or size > MAX_FILE_SIZE_BYTES:
        raise ValueError("File size is invalid or exceeds limit.")

    data = requested.read_bytes()
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("XML with DOCTYPE or ENTITY is not allowed.")

    # Parse securely using ElementTree (limited XPath). We already blocked DTD/ENTITY by content filter.
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"XML parse error: {e}") from e

    # Build the XPath expression strictly in the requested format
    xpath_expr = f"./tag[@id='{id_param}']"  # relative to root; equivalent to /tag[...] if root is the document root
    results: List[str] = []
    for elem in root.findall(xpath_expr):
        results.append(elem.text or "")
    return results


def _write_sample_file(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def main() -> None:
    if len(sys.argv) == 3:
        id_param = sys.argv[1]
        xml_file = sys.argv[2]
        try:
            results = execute_xpath(xml_file, id_param)
            for r in results:
                print(r)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Self tests (5 cases)
    xml_content = """<root>
  <tag id="a">Alpha</tag>
  <tag id="b">Beta</tag>
  <tag id="c">Gamma</tag>
  <group>
    <tag id="d">Delta</tag>
  </group>
  <tag id="a-2">Alpha2</tag>
</root>
"""
    sample = Path("sample97.xml").resolve()
    _write_sample_file(sample, xml_content)

    test_ids = ["a", "b", "x", "a-2", "d"]
    for tid in test_ids:
        print(f"Query id={tid}:")
        try:
            out = execute_xpath(str(sample), tid)
            if not out:
                print("(no results)")
            else:
                for line in out:
                    print(line)
        except Exception as e:
            print(f"Error: {e}")
        print("---")


if __name__ == "__main__":
    main()