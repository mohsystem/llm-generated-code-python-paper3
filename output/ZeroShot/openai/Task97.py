import os
import sys
import stat
import xml.etree.ElementTree as ET

def query_by_id(xml_file_path: str, id_value: str):
    if xml_file_path is None or id_value is None:
        raise ValueError("xml_file_path and id_value must not be None")

    st = os.lstat(xml_file_path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise OSError("Invalid file: not a regular file or is a symbolic link")

    parser = ET.XMLParser()
    tree = ET.parse(xml_file_path, parser=parser)
    root = tree.getroot()

    results = []
    for elem in root.findall('tag'):
        if elem.get('id') == id_value:
            results.append(ET.tostring(elem, encoding='unicode'))
    return results

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        out = query_by_id(sys.argv[1], sys.argv[2])
        for s in out:
            print(s)
    else:
        sample = """<?xml version="1.0" encoding="UTF-8"?>
<root>
  <tag id="1">Alpha</tag>
  <tag id="2"><inner>Beta</inner></tag>
  <tag id="3">Gamma</tag>
  <tag id="42">FortyTwo</tag>
  <tag id="x">X-Value</tag>
</root>
"""
        path = "sample97_py.xml"
        with open(path, "w", encoding="utf-8") as f:
            f.write(sample)

        test_ids = ["1", "2", "3", "42", "nope"]
        for tid in test_ids:
            res = query_by_id(path, tid)
            print(f"ID={tid} count={len(res)}")
            for s in res:
                print(s)